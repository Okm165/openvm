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

/// Assign segments to N workers by equal instruction count.
///
/// Splits contiguous segment ranges so each worker gets roughly the same total
/// instructions. Works for any number of workers. When there are more workers
/// than segments, excess workers get no assignment.
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

    let total_insns: u64 = segments.iter().map(|s| s.num_insns).sum();
    let target_per_worker = total_insns / num_provers as u64;

    let mut assignments = Vec::with_capacity(num_provers);
    let mut seg_idx = 0;

    for prover_idx in 0..num_provers {
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
            accumulated += segments[seg_idx].num_insns;
            seg_idx += 1;

            if accumulated >= target_per_worker {
                break;
            }

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
            (0.7..=1.4).contains(&balance_ratio),
            "Expected roughly balanced split, got ratio {:.2} (first={}, second={})",
            balance_ratio,
            first_insns,
            second_insns
        );
    }
}
