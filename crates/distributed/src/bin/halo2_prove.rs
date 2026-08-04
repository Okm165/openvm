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

    openvm_distributed::evm::halo2_prove_and_verify(
        &root_proof,
        &args.halo2_pk,
        args.kzg_params_dir.as_deref(),
    )?;

    info!("=== HALO2 TOTAL: {:?} ===", total_start.elapsed());
    Ok(())
}
