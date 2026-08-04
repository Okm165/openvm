use std::{path::Path, sync::Arc, time::Instant};

use eyre::{Context, Result};
use openvm_sdk::{
    halo2_params::CacheHalo2ParamsReader,
    prover::{Halo2Prover, InternalLayerMetadata},
    Sdk,
};
use openvm_stark_backend::codec::Encode;
use openvm_verify_stark_host::VmStarkProof;
use tracing::info;

use crate::client::WorkerClient;

pub struct EvmPipelineConfig<'a> {
    pub halo2_pk_cache: Option<&'a Path>,
    pub kzg_params_dir: Option<&'a Path>,
    pub halo2_subprocess: bool,
    pub grind_workers: Vec<WorkerClient>,
}

pub fn run(
    sdk: Sdk,
    proof: VmStarkProof,
    metadata: &mut InternalLayerMetadata,
    config: &EvmPipelineConfig<'_>,
) -> Result<()> {
    info!("=== EVM PIPELINE ===");
    let evm_start = Instant::now();

    #[cfg(feature = "cuda")]
    let _grind_guard = if !config.grind_workers.is_empty() {
        info!(
            "Distributed grinding: {} worker(s)",
            config.grind_workers.len()
        );
        let helper = Arc::new(RemoteGrindHelper::new(config.grind_workers.clone()));
        openvm_cuda_backend::set_distributed_grind_helper(helper);
        Some(DistributedGrindGuard)
    } else {
        None
    };

    info!("Phase 1/3: Root proving...");
    let root_start = Instant::now();
    let root_proof = {
        let root_prover = sdk.root_prover();
        let agg_prover = sdk.agg_prover();
        #[allow(unused_mut)]
        let mut root_engine = root_prover.create_engine();

        #[cfg(feature = "cuda")]
        root_engine.device_mut().set_cache_rs_code_matrix(true);

        root_prover.prove(proof, &root_engine, 8, |p| {
            agg_prover.wrap_proof(p, metadata)
        })?
    };
    info!("Root proving: {:?}", root_start.elapsed());

    #[cfg(feature = "cuda")]
    drop(_grind_guard);
    drop(sdk);

    if config.halo2_subprocess {
        return run_halo2_subprocess(&root_proof, config, evm_start);
    }

    run_halo2_inline(&root_proof, config, evm_start)
}

#[cfg(feature = "cuda")]
struct DistributedGrindGuard;

#[cfg(feature = "cuda")]
impl Drop for DistributedGrindGuard {
    fn drop(&mut self) {
        openvm_cuda_backend::clear_distributed_grind_helper();
    }
}

#[cfg(feature = "cuda")]
struct RemoteGrindHelper {
    workers: Vec<WorkerClient>,
    rt: tokio::runtime::Handle,
}

#[cfg(feature = "cuda")]
impl RemoteGrindHelper {
    fn new(workers: Vec<WorkerClient>) -> Self {
        let rt = tokio::runtime::Handle::current();
        Self { workers, rt }
    }
}

#[cfg(feature = "cuda")]
impl openvm_cuda_backend::DistributedGrindHelper for RemoteGrindHelper {
    fn num_workers(&self) -> u32 {
        self.workers.len() as u32
    }

    fn grind_remote(
        &self,
        sponge_state: &openvm_cuda_backend::DeviceBn254SpongeState,
        bits: u32,
        max_witness: u32,
        witness_step: u32,
    ) -> Result<Option<u32>, Box<dyn std::error::Error + Send + Sync>> {
        let state_bytes: Vec<u8> = unsafe {
            let ptr = sponge_state as *const _ as *const u8;
            let len = std::mem::size_of::<openvm_cuda_backend::DeviceBn254SpongeState>();
            std::slice::from_raw_parts(ptr, len).to_vec()
        };

        let workers = self.workers.clone();
        let result = self.rt.block_on(async {
            use tokio::sync::mpsc;

            let (tx, mut rx) = mpsc::channel::<u32>(1);

            for (i, worker) in workers.iter().enumerate() {
                let w = worker.clone();
                let req = crate::types::GrindRequest {
                    sponge_state_bytes: state_bytes.clone(),
                    bits,
                    min_witness: (i + 1) as u32, // offset for worker i
                    max_witness,
                    witness_step,
                };
                let tx = tx.clone();
                tokio::spawn(async move {
                    if let Ok(resp) = w.grind(&req).await {
                        if let Some(witness) = resp.witness {
                            let _ = tx.send(witness).await;
                        }
                    }
                });
            }
            drop(tx);

            rx.recv().await
        });

        Ok(result)
    }
}

pub fn halo2_prove_and_verify(
    root_proof: &openvm_stark_backend::proof::Proof<openvm_continuations::RootSC>,
    halo2_pk_path: &Path,
    kzg_params_dir: Option<&Path>,
) -> Result<u64> {
    let params_reader = match kzg_params_dir {
        Some(dir) => CacheHalo2ParamsReader::new(dir),
        None => CacheHalo2ParamsReader::new_with_default_params_dir(),
    };

    if !halo2_pk_path.exists() {
        return Err(eyre::eyre!(
            "Halo2PK not found at {:?}. Run --keygen-halo2 first.",
            halo2_pk_path
        ));
    }

    info!("Loading Halo2ProvingKey from {:?}", halo2_pk_path);
    let pk_start = Instant::now();
    let pk = openvm_sdk::fs::read_halo2_pk_from_file(halo2_pk_path)
        .wrap_err("failed to read Halo2PK")?;
    info!("Halo2PK loaded in {:?}", pk_start.elapsed());

    let verifier = openvm_sdk::solidity::generate_halo2_verifier_solidity(&pk, &params_reader)?;
    let prover = Halo2Prover::new(&params_reader, pk);

    info!("Starting Halo2 proof generation...");
    let prove_start = Instant::now();
    let evm_proof = prover.prove_for_evm(root_proof)?;
    info!("Halo2 proof generated in {:?}", prove_start.elapsed());

    info!("Verifying with EVM...");
    let verify_start = Instant::now();
    let gas_cost = Sdk::verify_evm_halo2_proof(&verifier, evm_proof, None)?;
    info!("EVM verification: {:?}", verify_start.elapsed());
    info!("Gas cost: {}", gas_cost);

    Ok(gas_cost)
}

fn run_halo2_inline(
    root_proof: &openvm_stark_backend::proof::Proof<openvm_continuations::RootSC>,
    config: &EvmPipelineConfig<'_>,
    evm_start: Instant,
) -> Result<()> {
    let cache_path = config
        .halo2_pk_cache
        .ok_or_else(|| eyre::eyre!("--halo2-pk-cache is required for the EVM pipeline"))?;

    info!("Phase 2/3: Halo2 wrapping...");
    let halo2_start = Instant::now();
    halo2_prove_and_verify(root_proof, cache_path, config.kzg_params_dir)?;
    info!("Halo2 wrapping total: {:?}", halo2_start.elapsed());
    info!("=== EVM PIPELINE TOTAL: {:?} ===", evm_start.elapsed());
    Ok(())
}

fn run_halo2_subprocess(
    root_proof: &openvm_stark_backend::proof::Proof<openvm_continuations::RootSC>,
    config: &EvmPipelineConfig<'_>,
    evm_start: Instant,
) -> Result<()> {
    let cache_path = config
        .halo2_pk_cache
        .ok_or_else(|| eyre::eyre!("--halo2-pk-cache is required with --halo2-subprocess"))?;

    let root_proof_path =
        std::env::temp_dir().join(format!("openvm_root_proof_{}.bin", std::process::id()));
    let root_proof_bytes = root_proof.encode_to_vec()?;
    std::fs::write(&root_proof_path, &root_proof_bytes)?;
    info!(
        "Root proof: {:?} ({:.1} MB)",
        root_proof_path,
        root_proof_bytes.len() as f64 / 1_048_576.0
    );
    drop(root_proof_bytes);

    info!("Phase 2/3: Launching Halo2 subprocess (openvm-halo2-prove)...");
    let exe_dir = std::env::current_exe()?.parent().unwrap().to_path_buf();
    let halo2_bin = exe_dir.join("openvm-halo2-prove");
    if !halo2_bin.exists() {
        return Err(eyre::eyre!(
            "openvm-halo2-prove not found at {:?}. Build with: cargo build --release -p openvm-distributed --features evm,cuda",
            halo2_bin
        ));
    }

    let mut cmd = std::process::Command::new(&halo2_bin);
    cmd.arg("--root-proof")
        .arg(&root_proof_path)
        .arg("--halo2-pk")
        .arg(cache_path);
    if let Some(dir) = config.kzg_params_dir {
        cmd.arg("--kzg-params-dir").arg(dir);
    }
    cmd.env(
        "RUST_LOG",
        std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
    );
    cmd.env(
        "JEMALLOC_SYS_WITH_MALLOC_CONF",
        "retain:true,background_thread:true,metadata_thp:always,dirty_decay_ms:-1,muzzy_decay_ms:-1",
    );

    info!(
        "exec() → halo2-prove (root proving took {:?})",
        evm_start.elapsed()
    );

    use std::os::unix::process::CommandExt;
    let err = cmd.exec();
    Err(eyre::eyre!("exec failed: {}", err))
}
