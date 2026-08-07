use std::{sync::Arc, time::Instant};

use clap::Parser;
use eyre::Result;
use openvm_circuit::arch::instructions::exe::VmExe;
use openvm_distributed::{client::WorkerClient, orchestrator::DistributedProver};
use openvm_sdk::{
    config::{AggregationSystemParams, AppConfig},
    Sdk, StdIn,
};
use openvm_sdk_config::{SdkVmConfig, TranspilerConfig as _};
use openvm_stark_sdk::config::{app_params_with_100_bits_security, MAX_APP_LOG_STACKED_HEIGHT};
use openvm_transpiler::{elf::Elf, openvm_platform::memory::MEM_SIZE, FromElf};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "openvm-orchestrator",
    about = "OpenVM distributed proving orchestrator"
)]
struct Args {
    /// Worker URLs (comma-separated)
    #[arg(long, value_delimiter = ',', required = true)]
    workers: Vec<String>,

    /// Path to guest ELF
    #[arg(long, required_unless_present = "keygen_halo2")]
    elf: Option<String>,

    /// Path to openvm.toml VM config
    #[arg(long)]
    config: Option<String>,

    /// Stdin file (auto-detects bitcode StdIn vs raw bytes)
    #[arg(long)]
    stdin: Option<std::path::PathBuf>,

    /// Run EVM pipeline (Root → Halo2 → EVM verify)
    #[cfg_attr(feature = "evm", arg(long))]
    #[cfg_attr(not(feature = "evm"), arg(long, hide = true))]
    evm: bool,

    /// KZG params directory
    #[arg(long, requires = "evm")]
    kzg_params_dir: Option<std::path::PathBuf>,

    /// Halo2 proving key cache path
    #[arg(long)]
    halo2_pk_cache: Option<std::path::PathBuf>,

    /// Generate Halo2 PK and exit
    #[cfg_attr(feature = "evm", arg(long))]
    #[cfg_attr(not(feature = "evm"), arg(long, hide = true))]
    keygen_halo2: bool,

    /// Disable worker-side leaf aggregation
    #[arg(long)]
    no_leaf_aggregate: bool,
}

fn load_stdin(args: &Args) -> Result<StdIn> {
    let Some(ref path) = args.stdin else {
        return Ok(StdIn::default());
    };
    let bytes = std::fs::read(path)
        .map_err(|e| eyre::eyre!("failed to read stdin file {:?}: {}", path, e))?;
    match bitcode::deserialize::<StdIn>(&bytes) {
        Ok(stdin) => {
            info!("stdin: {:?} ({} B, bitcode)", path, bytes.len());
            Ok(stdin)
        }
        Err(_) => {
            info!("stdin: {:?} ({} B, raw bytes)", path, bytes.len());
            Ok(StdIn::from_bytes(&bytes))
        }
    }
}

fn load_vm_config(args: &Args) -> Result<SdkVmConfig> {
    if let Some(ref config_path) = args.config {
        let config_str = std::fs::read_to_string(config_path)?;
        Ok(SdkVmConfig::from_toml(&config_str)?)
    } else {
        Ok(SdkVmConfig::riscv32())
    }
}

fn build_sdk(
    app_config: &AppConfig<SdkVmConfig>,
    agg_params: &AggregationSystemParams,
    args: &Args,
) -> Result<Sdk> {
    #[cfg(feature = "evm")]
    {
        let mut builder = Sdk::builder()
            .app_config(app_config.clone())
            .agg_params(agg_params.clone());
        if let Some(ref dir) = args.kzg_params_dir {
            builder = builder.halo2_params_dir(dir);
        }
        Ok(builder.build()?)
    }
    #[cfg(not(feature = "evm"))]
    {
        let _ = args;
        Ok(Sdk::new(app_config.clone(), agg_params.clone())?)
    }
}

async fn check_workers(
    worker_urls: &[String],
    secret: &Option<String>,
) -> Result<Vec<WorkerClient>> {
    let our_version = env!("CARGO_PKG_VERSION");

    let clients: Vec<_> = worker_urls
        .iter()
        .filter_map(|url| WorkerClient::new(url, secret.clone()).ok())
        .collect();

    let mut handles = Vec::with_capacity(clients.len());
    for client in clients {
        handles.push(tokio::spawn(async move {
            match client.health().await {
                Ok(health) => {
                    if health.version.as_deref() != Some(our_version) {
                        tracing::warn!("Version mismatch with {}", client.base_url());
                    }
                    info!("{} — {}", client.base_url(), health.status);
                    Some(client)
                }
                Err(e) => {
                    tracing::warn!("{} unreachable: {}", client.base_url(), e);
                    None
                }
            }
        }));
    }

    let mut reachable = Vec::new();
    for handle in handles {
        if let Ok(Some(client)) = handle.await {
            reachable.push(client);
        }
    }
    Ok(reachable)
}

async fn preload_halo2_on_workers(
    workers: &[WorkerClient],
    halo2_pk_path: Option<&std::path::Path>,
    kzg_params_dir: Option<&std::path::Path>,
) -> Result<()> {
    let Some(pk_path) = halo2_pk_path else {
        return Ok(());
    };

    let request = openvm_distributed::types::Halo2PreloadRequest {
        halo2_pk_path: pk_path.to_string_lossy().to_string(),
        kzg_params_dir: kzg_params_dir.map(|p| p.to_string_lossy().to_string()),
    };

    let mut handles = Vec::with_capacity(workers.len());
    for (i, worker) in workers.iter().enumerate() {
        let req = request.clone();
        let url = worker.base_url().to_string();
        let w = worker.clone();
        handles.push(tokio::spawn(async move {
            match w.halo2_preload(&req).await {
                Ok(resp) if resp.ready => {
                    info!("Worker {} ({}) — Halo2 OK", i, url);
                }
                Ok(_) => {
                    tracing::warn!("Worker {} ({}) — Halo2 NOT ready", i, url);
                }
                Err(e) => {
                    tracing::warn!("Worker {} ({}) — Halo2 check failed: {}", i, url, e);
                }
            }
        }));
    }
    for handle in handles {
        let _ = handle.await;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let secret = std::env::var("OPENVM_WORKER_SECRET").ok();

    openvm_distributed::log_system_memory();
    info!("Workers: {:?}", args.workers);

    let workers = if args.keygen_halo2 {
        vec![]
    } else {
        let w = check_workers(&args.workers, &secret).await?;
        if w.is_empty() {
            return Err(eyre::eyre!("No reachable workers"));
        }
        info!("{} worker(s) available", w.len());
        w
    };

    // Preload Halo2 PK check on all workers (fast sanity check)
    if args.evm && !args.keygen_halo2 {
        preload_halo2_on_workers(
            &workers,
            args.halo2_pk_cache.as_deref(),
            args.kzg_params_dir.as_deref(),
        )
        .await?;
    }

    let vm_config = load_vm_config(&args)?;
    let stdin = load_stdin(&args)?;

    let app_params = app_params_with_100_bits_security(MAX_APP_LOG_STACKED_HEIGHT);
    let agg_params = AggregationSystemParams::default();
    let app_config = AppConfig::new(vm_config.clone(), app_params);
    let sdk = build_sdk(&app_config, &agg_params, &args)?;

    #[cfg(feature = "evm")]
    if args.keygen_halo2 {
        return run_keygen_halo2(&sdk, &args);
    }
    #[cfg(not(feature = "evm"))]
    if args.keygen_halo2 {
        return Err(eyre::eyre!("--keygen-halo2 requires the `evm` feature"));
    }

    let elf_path = args
        .elf
        .as_ref()
        .ok_or_else(|| eyre::eyre!("--elf is required for proving"))?;
    info!("Loading ELF from: {}", elf_path);
    let elf_bytes = std::fs::read(elf_path)?;
    let elf = Elf::decode(&elf_bytes, MEM_SIZE as u32)?;
    let exe = Arc::new(VmExe::from_elf(elf, vm_config.transpiler())?);

    let mut prover = DistributedProver::new(sdk, exe, stdin, workers);

    if args.no_leaf_aggregate {
        prover.set_leaf_aggregate(false);
    }

    let start = Instant::now();
    let result = prover.prove().await?;

    use openvm_stark_backend::codec::Encode;
    info!(
        "Proved in {:?} ({} bytes)",
        start.elapsed(),
        result.proof.encode_to_vec()?.len()
    );

    let agg_vk = prover.sdk().agg_vk();
    verify_stark_proof(&agg_vk, result.baseline, &result.proof)?;

    #[cfg(feature = "evm")]
    if args.evm {
        let workers: Vec<_> = prover.workers().to_vec();
        drop(prover);
        // Release all GPU memory so workers on the same node have full VRAM
        // for root/Halo2. The fresh pool's VA reservation is virtual-only and
        // does not consume physical GPU memory.
        openvm_distributed::release_and_reinit_pool();

        let mut metadata = result.metadata;
        let config = openvm_distributed::evm::EvmPipelineConfig {
            halo2_pk_cache: args.halo2_pk_cache.as_deref(),
            kzg_params_dir: args.kzg_params_dir.as_deref(),
            workers: workers.clone(),
        };
        openvm_distributed::evm::run(result.proof, &mut metadata, &config).await?;

        for w in &workers {
            let _ = w.release_gpu().await;
        }
    }

    #[cfg(not(feature = "evm"))]
    if args.evm {
        tracing::warn!(
            "--evm requires the `evm` feature. Rebuild with: cargo build --features evm,cuda -p openvm-distributed"
        );
    }

    Ok(())
}

fn verify_stark_proof(
    agg_vk: &openvm_stark_backend::keygen::types::MultiStarkVerifyingKey<openvm_sdk::SC>,
    baseline: openvm_verify_stark_host::vk::VerificationBaseline,
    proof: &openvm_verify_stark_host::VmStarkProof,
) -> Result<()> {
    let verify_start = Instant::now();
    Sdk::verify_proof(agg_vk.clone(), baseline, proof)
        .map_err(|e| eyre::eyre!("proof verification failed: {:?}", e))?;
    info!("Proof VERIFIED in {:?}", verify_start.elapsed());
    Ok(())
}

#[cfg(feature = "evm")]
fn run_keygen_halo2(sdk: &Sdk, args: &Args) -> Result<()> {
    let path = args
        .halo2_pk_cache
        .as_ref()
        .ok_or_else(|| eyre::eyre!("--halo2-pk-cache is required with --keygen-halo2"))?;

    if path.exists() {
        info!("Halo2 PK exists at {:?}, skipping", path);
    } else {
        info!("Generating Halo2 PK...");
        let start = Instant::now();
        let pk = sdk.halo2_pk();
        openvm_sdk::fs::write_halo2_pk_to_file(path, &pk)?;
        info!("Halo2 PK saved to {:?} in {:?}", path, start.elapsed());
    }
    Ok(())
}
