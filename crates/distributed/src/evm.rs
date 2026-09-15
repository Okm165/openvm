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

pub struct EvmPipelineResult {
    pub evm_proof_json: Option<String>,
    pub gas_cost: u64,
    /// Hex-encoded deployment bytecode of the verifier contract matching our PK.
    pub verifier_bytecode_hex: Option<String>,
}

/// Runs the full EVM pipeline:
///   Phase 1: Root proving (worker GPU)
///   Phase 2: Halo2 proving (worker GPU)
///   Phase 3: EVM verification (orchestrator CPU — Revm)
pub async fn run(
    proof: VmStarkProof,
    metadata: &mut InternalLayerMetadata,
    config: &EvmPipelineConfig<'_>,
) -> Result<EvmPipelineResult> {
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

    // ── Phase 1: Root proving (worker GPU) ────────────────────────────────

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

    // ── Phase 2: Halo2 proving (worker GPU) ───────────────────────────────

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
                    "Halo2 proving: {:?} (worker: {}ms)",
                    halo2_start.elapsed(),
                    resp.proving_time_ms,
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

    let evm_proof_json = halo2_resp
        .evm_proof_json
        .ok_or_else(|| eyre::eyre!("Worker returned no EVM proof data"))?;

    // ── Phase 3: EVM verification (orchestrator CPU) ──────────────────────
    //
    // Verifier generation and Revm simulation run on the orchestrator so
    // that workers stay focused on GPU proving only.

    info!("Orchestrator: generating Halo2 verifier from PK...");
    let verify_start = Instant::now();

    let evm_proof: openvm_sdk::types::EvmProof = serde_json::from_str(&evm_proof_json)
        .map_err(|e| eyre::eyre!("deserialize EvmProof: {}", e))?;

    let pk_data = std::fs::read(cache_path)
        .map_err(|e| eyre::eyre!("read Halo2 PK: {}", e))?;
    let pk: openvm_sdk::keygen::Halo2ProvingKey = {
        let mut cursor = std::io::Cursor::new(&pk_data);
        openvm_stark_backend::codec::Decode::decode(&mut cursor)
            .map_err(|e| eyre::eyre!("decode Halo2 PK: {}", e))?
    };
    drop(pk_data);

    let params_reader = match config.kzg_params_dir {
        Some(dir) => openvm_sdk::halo2_params::CacheHalo2ParamsReader::new(dir),
        None => openvm_sdk::halo2_params::CacheHalo2ParamsReader::new_with_default_params_dir(),
    };

    let verifier =
        openvm_sdk::solidity::generate_halo2_verifier_solidity(&pk, &params_reader)?;
    drop(pk);
    info!("Verifier generated in {:?}", verify_start.elapsed());

    let verifier_bytecode_hex: String = verifier
        .artifact
        .bytecode
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    info!(
        "Verifier deployment bytecode: {} bytes",
        verifier.artifact.bytecode.len()
    );

    info!("Orchestrator: EVM verification via Revm...");
    let revm_start = Instant::now();
    let gas_cost =
        openvm_sdk::Sdk::verify_evm_halo2_proof(&verifier, evm_proof, None)?;
    info!(
        "EVM verify: {:?}, gas: {}",
        revm_start.elapsed(),
        gas_cost
    );

    info!(
        "=== EVM PIPELINE TOTAL: {:?} === Gas: {}",
        evm_start.elapsed(),
        gas_cost
    );

    Ok(EvmPipelineResult {
        evm_proof_json: Some(evm_proof_json),
        gas_cost,
        verifier_bytecode_hex: Some(verifier_bytecode_hex),
    })
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
