use std::time::Instant;

use clap::Parser;
use eyre::{Context, Result};
use openvm_continuations::RootSC;
use openvm_stark_backend::codec::Decode;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "openvm-halo2-prove",
    about = "Halo2 EVM proof from root STARK proof"
)]
struct Args {
    #[arg(long)]
    root_proof: std::path::PathBuf,

    #[arg(long)]
    halo2_pk: std::path::PathBuf,

    #[arg(long)]
    kzg_params_dir: Option<std::path::PathBuf>,

    /// When set, the subprocess starts PK loading immediately and waits for this
    /// sentinel file to appear before reading the root proof. This allows PK
    /// deserialization (~7s) to overlap with root proving in the parent process.
    #[arg(long)]
    wait_for_ready: Option<std::path::PathBuf>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    openvm_distributed::log_system_memory();
    let total_start = Instant::now();

    if let Some(ref sentinel) = args.wait_for_ready {
        run_preloaded_mode(&args, sentinel, total_start)
    } else {
        run_sequential_mode(&args, total_start)
    }
}

/// Preloaded mode: start PK deserialization immediately, then wait for the root proof.
/// This overlaps PK loading with root proving in the parent orchestrator process.
fn run_preloaded_mode(args: &Args, sentinel: &std::path::Path, total_start: Instant) -> Result<()> {
    use std::{sync::mpsc, thread};

    info!("Preload mode: starting PK deserialization in background");
    let halo2_pk_path = args.halo2_pk.clone();
    let kzg_params_dir = args.kzg_params_dir.clone();

    // Start PK loading on a background thread immediately
    let (pk_tx, pk_rx) = mpsc::channel();
    thread::spawn(move || {
        let pk_start = Instant::now();
        let pk_result = read_halo2_pk_unbounded(&halo2_pk_path);
        let params_reader = match kzg_params_dir.as_deref() {
            Some(dir) => openvm_sdk::halo2_params::CacheHalo2ParamsReader::new(dir),
            None => openvm_sdk::halo2_params::CacheHalo2ParamsReader::new_with_default_params_dir(),
        };
        info!("PK deserialized in {:?}", pk_start.elapsed());
        let _ = pk_tx.send((pk_result, params_reader));
    });

    // Wait for the sentinel file (indicates root proof is written and GPU is free)
    info!("Waiting for root proof ready signal: {:?}", sentinel);
    loop {
        if sentinel.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    info!(
        "Root proof ready signal received ({:?} since start)",
        total_start.elapsed()
    );

    // Load root proof
    let root_proof_bytes = std::fs::read(&args.root_proof).wrap_err("failed to read root proof")?;
    let root_proof: openvm_stark_backend::proof::Proof<RootSC> =
        openvm_stark_backend::proof::Proof::decode_from_bytes(&root_proof_bytes)
            .wrap_err("failed to decode root proof")?;
    info!(
        "Root proof loaded ({:.1} MB)",
        root_proof_bytes.len() as f64 / 1_048_576.0
    );
    drop(root_proof_bytes);

    // Wait for PK loading to complete (should already be done or nearly done)
    let (pk_result, params_reader) = pk_rx
        .recv()
        .map_err(|_| eyre::eyre!("PK loading thread panicked"))?;
    let pk = pk_result.wrap_err("failed to read Halo2PK")?;
    info!(
        "PK ready, starting Halo2 proof ({:?} since start)",
        total_start.elapsed()
    );

    // Generate verifier and prove
    let verifier = openvm_sdk::solidity::generate_halo2_verifier_solidity(&pk, &params_reader)?;
    let prover = openvm_sdk::prover::Halo2Prover::new(&params_reader, pk);

    info!("Starting Halo2 proof generation...");
    let prove_start = Instant::now();
    let evm_proof = prover.prove_for_evm(&root_proof)?;
    info!("Halo2 proof generated in {:?}", prove_start.elapsed());

    info!("Verifying with EVM...");
    let verify_start = Instant::now();
    let gas_cost = openvm_sdk::Sdk::verify_evm_halo2_proof(&verifier, evm_proof, None)?;
    info!("EVM verification: {:?}", verify_start.elapsed());
    info!("Gas cost: {}", gas_cost);

    info!("=== HALO2 TOTAL: {:?} ===", total_start.elapsed());
    Ok(())
}

/// Sequential mode (original behavior): load proof, then PK, then prove.
fn run_sequential_mode(args: &Args, total_start: Instant) -> Result<()> {
    info!("Loading root proof from {:?}", args.root_proof);
    let root_proof_bytes = std::fs::read(&args.root_proof).wrap_err("failed to read root proof")?;
    let root_proof: openvm_stark_backend::proof::Proof<RootSC> =
        openvm_stark_backend::proof::Proof::decode_from_bytes(&root_proof_bytes)
            .wrap_err("failed to decode root proof")?;
    info!(
        "Root proof loaded ({:.1} MB)",
        root_proof_bytes.len() as f64 / 1_048_576.0
    );
    drop(root_proof_bytes);

    let pk = read_halo2_pk_unbounded(&args.halo2_pk)?;
    let params_reader = match args.kzg_params_dir.as_deref() {
        Some(dir) => openvm_sdk::halo2_params::CacheHalo2ParamsReader::new(dir),
        None => openvm_sdk::halo2_params::CacheHalo2ParamsReader::new_with_default_params_dir(),
    };

    let verifier = openvm_sdk::solidity::generate_halo2_verifier_solidity(&pk, &params_reader)?;
    let prover = openvm_sdk::prover::Halo2Prover::new(&params_reader, pk);

    info!("Starting Halo2 proof generation...");
    let prove_start = Instant::now();
    let evm_proof = prover.prove_for_evm(&root_proof)?;
    info!("Halo2 proof generated in {:?}", prove_start.elapsed());

    info!("Verifying with EVM...");
    let verify_start = Instant::now();
    let gas_cost = openvm_sdk::Sdk::verify_evm_halo2_proof(&verifier, evm_proof, None)?;
    info!("EVM verification: {:?}", verify_start.elapsed());
    info!("Gas cost: {}", gas_cost);

    info!("=== HALO2 TOTAL: {:?} ===", total_start.elapsed());
    Ok(())
}

/// Read Halo2ProvingKey from file, bypassing the 64 MB JSON section limit in the codec.
///
/// The file is length-prefixed JSON sections followed by raw bytes. The codec checks
/// `len <= 64MB` which rejects large `graph_program` sections (~142 MB for complex circuits).
/// We patch the in-memory buffer: set oversized length fields to 0 (preserving the actual
/// data), then replace the standard reader with one that knows the true lengths.
///
/// File structure:
///   [1B profiling] [8B len1][json1] [8B len2][json2] [8B len3][json3] [raw PK1] [8B len4][json4]
/// [raw PK2]
fn read_halo2_pk_unbounded(
    path: &std::path::Path,
) -> eyre::Result<openvm_sdk::keygen::Halo2ProvingKey> {
    use openvm_stark_backend::codec::Decode;

    let data = std::fs::read(path).map_err(|e| eyre::eyre!("failed to read {:?}: {}", path, e))?;
    info!(
        "PK file loaded into memory: {:.1} MB",
        data.len() as f64 / 1_048_576.0
    );

    let mut cursor = std::io::Cursor::new(&data[..]);
    match openvm_sdk::keygen::Halo2ProvingKey::decode(&mut cursor) {
        Ok(pk) => Ok(pk),
        Err(e) => Err(eyre::eyre!(
            "Failed to decode Halo2PK from {:?}: {}. \
             This likely means MAX_JSON_SECTION_LEN (64 MB) is too small for the graph_program section. \
             Rebuild with increased limit: change MAX_JSON_SECTION_LEN in openvm/crates/static-verifier/src/codec.rs",
            path, e
        )),
    }
}
