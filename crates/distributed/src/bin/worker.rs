use clap::Parser;
use openvm_distributed::server::create_router;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "openvm-worker", about = "OpenVM distributed proving worker")]
struct Args {
    /// Port to listen on
    #[arg(long, default_value = "8002")]
    port: u16,

    /// Bind address
    #[arg(long, default_value = "0.0.0.0")]
    bind: String,
}

fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let secret = std::env::var("OPENVM_WORKER_SECRET").ok();

    openvm_distributed::log_system_memory();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let router = create_router(secret);
        let addr = format!("{}:{}", args.bind, args.port);
        let listener = TcpListener::bind(&addr).await?;
        info!("Worker listening on {}", addr);

        axum::serve(listener, router).await?;
        Ok::<(), eyre::Report>(())
    })?;

    Ok(())
}
