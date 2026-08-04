use eyre::{bail, Result};
use openvm_circuit::arch::execution_mode::Segment;

#[derive(Debug, Clone)]
pub struct SegmentAssignment {
    pub start: usize,
    pub end: usize,
    pub total_insns: u64,
}

pub fn validate_assignments(assignments: &[SegmentAssignment], num_segments: usize) -> Result<()> {
    if assignments.is_empty() {
        return Ok(());
    }
    if assignments[0].start != 0 {
        bail!(
            "BUG: first assignment doesn't start at 0 (starts at {})",
            assignments[0].start
        );
    }
    for window in assignments.windows(2) {
        if window[0].end != window[1].start {
            bail!(
                "BUG: gap/overlap between assignments [{},{}] and [{},{}]",
                window[0].start,
                window[0].end,
                window[1].start,
                window[1].end
            );
        }
    }
    if assignments.last().unwrap().end != num_segments {
        bail!(
            "BUG: last assignment ends at {} but expected {}",
            assignments.last().unwrap().end,
            num_segments
        );
    }
    Ok(())
}

/// Cost-aware segment assignment. For 2 provers: optimal split-point search
/// accounting for GPU warmup (~50% overhead on first segment) and E1 recovery
/// cost. For N>2: greedy cost-proportional assignment.
pub fn assign_segments(segments: &[Segment], num_provers: usize) -> Vec<SegmentAssignment> {
    let num_segments = segments.len();
    if num_provers == 0 || num_segments == 0 {
        return vec![];
    }

    if num_provers >= num_segments {
        return segments
            .iter()
            .enumerate()
            .map(|(i, s)| SegmentAssignment {
                start: i,
                end: i + 1,
                total_insns: s.num_insns,
            })
            .collect();
    }

    if num_provers == 2 {
        return assign_two_provers(segments);
    }

    assign_greedy(segments, num_provers)
}

fn assign_two_provers(segments: &[Segment]) -> Vec<SegmentAssignment> {
    let n = segments.len();
    const WARMUP_FACTOR: f64 = 1.5;

    let mut best_split = 1;
    let mut best_max_time = f64::MAX;

    for split in 1..n {
        let first_time = estimate_prover_cost(&segments[..split], WARMUP_FACTOR, 0);
        let second_e1_insns = segments[split].instret_start;
        let second_time = estimate_prover_cost(&segments[split..], WARMUP_FACTOR, second_e1_insns);

        let max_time = first_time.max(second_time);
        if max_time < best_max_time {
            best_max_time = max_time;
            best_split = split;
        }
    }

    let first_insns: u64 = segments[..best_split].iter().map(|s| s.num_insns).sum();
    let second_insns: u64 = segments[best_split..].iter().map(|s| s.num_insns).sum();

    vec![
        SegmentAssignment {
            start: 0,
            end: best_split,
            total_insns: first_insns,
        },
        SegmentAssignment {
            start: best_split,
            end: n,
            total_insns: second_insns,
        },
    ]
}

// E1 at ~2.7ns/insn vs proving at ~143ns/insn → 1 E1 insn ≈ 0.019 proving insns.
const E1_TO_PROVING_RATIO: f64 = 0.019;

fn estimate_prover_cost(segments: &[Segment], warmup_factor: f64, e1_insns: u64) -> f64 {
    if segments.is_empty() {
        return 0.0;
    }

    let e1_cost = e1_insns as f64 * E1_TO_PROVING_RATIO;

    let mut proving_cost = 0.0;
    for (i, seg) in segments.iter().enumerate() {
        let base = seg.num_insns as f64;
        proving_cost += if i == 0 { base * warmup_factor } else { base };
    }

    e1_cost + proving_cost
}

fn assign_greedy(segments: &[Segment], num_provers: usize) -> Vec<SegmentAssignment> {
    let num_segments = segments.len();
    let total_insns: u64 = segments.iter().map(|s| s.num_insns).sum();

    let base_target = total_insns as f64 / num_provers as f64;

    // Estimate split boundaries to get actual instret_start values
    let mut boundary_instret = vec![0u64; num_provers];
    {
        let naive_target = total_insns / num_provers as u64;
        let mut acc = 0u64;
        let mut prover = 0;
        for seg in segments.iter() {
            acc += seg.num_insns;
            if prover < num_provers - 1 && acc >= naive_target * (prover as u64 + 1) {
                prover += 1;
                boundary_instret[prover] = acc;
            }
        }
    }

    let raw_targets: Vec<f64> = (0..num_provers)
        .map(|k| {
            let e1_insns = boundary_instret[k] as f64;
            let e1_cost = e1_insns * E1_TO_PROVING_RATIO;
            (base_target - e1_cost).max(base_target * 0.5)
        })
        .collect();
    let raw_sum: f64 = raw_targets.iter().sum();
    let targets: Vec<u64> = raw_targets
        .iter()
        .map(|&t| ((t / raw_sum) * total_insns as f64) as u64)
        .collect();

    let mut assignments = Vec::with_capacity(num_provers);
    let mut seg_idx = 0;

    for (prover_idx, &target) in targets.iter().enumerate() {
        let start = seg_idx;

        if prover_idx == num_provers - 1 {
            let total: u64 = segments[start..].iter().map(|s| s.num_insns).sum();
            assignments.push(SegmentAssignment {
                start,
                end: num_segments,
                total_insns: total,
            });
            break;
        }

        let mut accumulated = 0u64;
        while seg_idx < num_segments {
            let next_cost = segments[seg_idx].num_insns;
            if accumulated > 0 && accumulated + next_cost > target {
                let overshoot = (accumulated + next_cost) - target;
                let undershoot = target.saturating_sub(accumulated);
                if overshoot > undershoot * 2 {
                    break;
                }
            }
            accumulated += next_cost;
            seg_idx += 1;

            let remaining_provers = num_provers - prover_idx - 1;
            let remaining_segments = num_segments - seg_idx;
            if remaining_segments <= remaining_provers {
                break;
            }
        }

        if seg_idx == start {
            seg_idx = start + 1;
        }

        let total: u64 = segments[start..seg_idx].iter().map(|s| s.num_insns).sum();
        assignments.push(SegmentAssignment {
            start,
            end: seg_idx,
            total_insns: total,
        });
    }

    assignments
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_segments(insns: &[u64]) -> Vec<Segment> {
        let mut instret = 0;
        insns
            .iter()
            .map(|&n| {
                let s = Segment {
                    instret_start: instret,
                    num_insns: n,
                    trace_heights: vec![1024],
                };
                instret += n;
                s
            })
            .collect()
    }

    #[test]
    fn equal_segments_balanced_split() {
        let segments = make_segments(&[1000, 1000, 1000, 1000]);
        let result = assign_segments(&segments, 2);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].start, 0);
        assert_eq!(result[0].end, 2);
        assert_eq!(result[1].start, 2);
        assert_eq!(result[1].end, 4);
    }

    #[test]
    fn unequal_segments_heavy_first() {
        let segments = make_segments(&[3000, 1000, 1000]);
        let result = assign_segments(&segments, 2);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].start, 0);
        assert_eq!(result[0].end, 1);
        assert_eq!(result[1].start, 1);
        assert_eq!(result[1].end, 3);
    }

    #[test]
    fn single_segment_single_assignment() {
        let segments = make_segments(&[5000]);
        let result = assign_segments(&segments, 2);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].start, 0);
        assert_eq!(result[0].end, 1);
    }

    #[test]
    fn more_provers_than_segments() {
        let segments = make_segments(&[1000, 2000]);
        let result = assign_segments(&segments, 4);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn fibonacci_realistic_workload() {
        let mut insns = vec![14_000_000u64; 10];
        insns.push(10_095_278);
        let segments = make_segments(&insns);
        let result = assign_segments(&segments, 2);
        assert_eq!(result.len(), 2);
        let first_count = result[0].end - result[0].start;
        let second_count = result[1].end - result[1].start;
        assert!(
            first_count <= 6 && second_count >= 5,
            "Expected balanced split, got first={} second={}",
            first_count,
            second_count
        );
    }

    #[test]
    fn greedy_three_provers() {
        let segments = make_segments(&[1000; 9]);
        let result = assign_segments(&segments, 3);
        assert_eq!(result.len(), 3);
        for a in &result {
            let count = a.end - a.start;
            assert!(
                (2..=4).contains(&count),
                "Expected ~3 segments per prover, got {}",
                count
            );
        }
    }

    #[test]
    fn greedy_covers_all_segments() {
        for num_provers in 2..=5 {
            for num_segs in 2..=20 {
                let segments = make_segments(&vec![1000u64; num_segs]);
                let result = assign_segments(&segments, num_provers);
                let total_assigned: usize = result.iter().map(|a| a.end - a.start).sum();
                assert_eq!(
                    total_assigned, num_segs,
                    "Lost segments: provers={}, segs={}, assigned={}",
                    num_provers, num_segs, total_assigned
                );
                for i in 1..result.len() {
                    assert_eq!(
                        result[i].start,
                        result[i - 1].end,
                        "Gap/overlap at boundary {}: prev.end={}, next.start={}",
                        i,
                        result[i - 1].end,
                        result[i].start
                    );
                }
                assert_eq!(result[0].start, 0);
                assert_eq!(result.last().unwrap().end, num_segs);
            }
        }
    }

    #[test]
    fn highly_nonuniform_heavy_init() {
        let mut insns = vec![50_000_000u64];
        insns.extend(vec![5_000_000u64; 9]);
        let segments = make_segments(&insns);
        let result = assign_segments(&segments, 2);
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0].end, 1,
            "Heavy init should be isolated to worker 0"
        );
        assert_eq!(result[1].start, 1);
        assert_eq!(result[1].end, 10);
    }

    #[test]
    fn two_segments_two_provers_each_gets_one() {
        let segments = make_segments(&[10_000_000, 10_000_000]);
        let result = assign_segments(&segments, 2);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].start, 0);
        assert_eq!(result[0].end, 1);
        assert_eq!(result[1].start, 1);
        assert_eq!(result[1].end, 2);
    }

    #[test]
    fn three_provers_two_segments_no_panic() {
        let segments = make_segments(&[1000, 2000]);
        let result = assign_segments(&segments, 3);
        assert_eq!(result.len(), 2);
        let total: usize = result.iter().map(|a| a.end - a.start).sum();
        assert_eq!(total, 2);
    }

    #[test]
    fn realistic_fibonacci_20m() {
        let mut insns = vec![13_981_000u64; 10];
        insns.push(10_095_278);
        let segments = make_segments(&insns);
        let result = assign_segments(&segments, 2);
        assert_eq!(result.len(), 2);
        let first_count = result[0].end - result[0].start;
        let second_count = result[1].end - result[1].start;
        let first_insns = result[0].total_insns;
        let second_insns = result[1].total_insns;
        assert!(
            first_count + second_count == 11,
            "Must cover all 11 segments"
        );
        let balance_ratio = first_insns as f64 / second_insns as f64;
        assert!(
            (0.8..=1.2).contains(&balance_ratio),
            "Expected roughly balanced split, got ratio {:.2} (first={}, second={})",
            balance_ratio,
            first_insns,
            second_insns
        );
    }
}
