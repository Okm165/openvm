use std::{path::Path, time::Instant};

use eyre::{Context, Result};
use openvm_sdk::prover::InternalLayerMetadata;
use openvm_stark_backend::codec::Encode;
use openvm_verify_stark_host::VmStarkProof;
use tracing::info;

use crate::client::WorkerClient;

pub struct EvmPipelineConfig<'a> {
    pub halo2_pk_cache: Option<&'a Path>,
    pub kzg_params_dir: Option<&'a Path>,
    pub workers: Vec<WorkerClient>,
}

pub async fn run(
    proof: VmStarkProof,
    metadata: &mut InternalLayerMetadata,
    config: &EvmPipelineConfig<'_>,
) -> Result<()> {
    if config.workers.is_empty() {
        return Err(eyre::eyre!(
            "EVM pipeline requires at least one worker (2+ recommended)"
        ));
    }

    info!("=== EVM PIPELINE ({} workers) ===", config.workers.len());
    let evm_start = Instant::now();
    let num_workers = config.workers.len();

    let rr_start = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_micros() as usize)
        % num_workers;

    let cache_path = config
        .halo2_pk_cache
        .ok_or_else(|| eyre::eyre!("--halo2-pk-cache required for EVM pipeline"))?;

    // ── Phase 1: Root proving ────────────────────────────────────────────
    //
    // Try the primary worker; if it fails, retry on the next.

    let proof_bytes = proof.encode_to_vec().wrap_err("encode VmStarkProof")?;
    let metadata_bytes = encode_metadata(metadata);
    let root_task = crate::types::RootProveTask {
        proof_bytes,
        metadata_bytes,
    };

    let mut root_resp = None;
    for attempt in 0..num_workers {
        let root_worker_idx = (rr_start + attempt) % num_workers;
        let root_worker = &config.workers[root_worker_idx];

        info!(
            "Root proving → worker {} ({}){}",
            root_worker_idx,
            root_worker.base_url(),
            if attempt > 0 { " (retry)" } else { "" }
        );
        let root_start = Instant::now();
        match root_worker.prove_root(&root_task).await {
            Ok(resp) => {
                info!(
                    "Root proving: {:?} (worker: {}ms)",
                    root_start.elapsed(),
                    resp.proving_time_ms
                );
                root_resp = Some(resp);
                break;
            }
            Err(e) => {
                tracing::warn!(
                    "Root proving failed on worker {} ({}): {}",
                    root_worker_idx,
                    root_worker.base_url(),
                    e
                );
                if attempt + 1 < num_workers {
                    info!("Retrying root proving on next worker...");
                }
            }
        }
    }

    let root_resp = root_resp
        .ok_or_else(|| eyre::eyre!("Root proving failed on all {} workers", num_workers))?;

    // ── Phase 2: Halo2 proving ───────────────────────────────────────────
    //
    // The worker drops all STARK state, releases the VPMM pool (returning
    // all physical pages to the driver), and proves Halo2 in-process.
    //
    // If Halo2 fails on the primary target, retry on the next worker.

    let halo2_task = crate::types::Halo2ProveTask {
        root_proof_bytes: root_resp.root_proof_bytes,
        halo2_pk_path: cache_path.to_string_lossy().to_string(),
        kzg_params_dir: config
            .kzg_params_dir
            .map(|p| p.to_string_lossy().to_string()),
    };

    let mut halo2_resp = None;
    for attempt in 0..num_workers {
        let halo2_worker_idx = (rr_start + 1 + attempt) % num_workers;
        let halo2_worker = &config.workers[halo2_worker_idx];

        info!(
            "Halo2 proving → worker {} ({}){}",
            halo2_worker_idx,
            halo2_worker.base_url(),
            if attempt > 0 { " (retry)" } else { "" }
        );

        let halo2_start = Instant::now();
        match halo2_worker.prove_halo2(&halo2_task).await {
            Ok(resp) => {
                info!(
                    "Halo2 proving: {:?} (worker: {}ms, gas={})",
                    halo2_start.elapsed(),
                    resp.proving_time_ms,
                    resp.gas_cost
                );
                halo2_resp = Some(resp);
                break;
            }
            Err(e) => {
                tracing::warn!(
                    "Halo2 failed on worker {} ({}): {}",
                    halo2_worker_idx,
                    halo2_worker.base_url(),
                    e
                );
                if attempt + 1 < num_workers {
                    info!("Retrying Halo2 on next worker...");
                }
            }
        }
    }

    let halo2_resp = halo2_resp
        .ok_or_else(|| eyre::eyre!("Halo2 proving failed on all {} workers", num_workers))?;

    info!(
        "=== EVM PIPELINE TOTAL: {:?} === Gas: {}",
        evm_start.elapsed(),
        halo2_resp.gas_cost
    );

    Ok(())
}

fn encode_metadata(metadata: &InternalLayerMetadata) -> Vec<u8> {
    let mut buf = Vec::with_capacity(9);
    buf.extend_from_slice(&metadata.internal_recursive_layer.to_le_bytes());
    buf.extend_from_slice(&metadata.internal_node_idx.to_le_bytes());
    buf.push(match metadata.proofs_type {
        openvm_continuations::circuit::inner::ProofsType::Vm => 0,
        openvm_continuations::circuit::inner::ProofsType::Deferral => 1,
        openvm_continuations::circuit::inner::ProofsType::Mix => 2,
        openvm_continuations::circuit::inner::ProofsType::Combined => 3,
    });
    buf
}
