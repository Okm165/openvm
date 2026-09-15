use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use tracing::{error, info};

use crate::types::ErrorResponse;

struct AppState {
    proving_since: Option<std::time::Instant>,
}

// SAFETY: Single-threaded tokio runtime (Builder::new_current_thread()).
// AppState never crosses thread boundaries.
unsafe impl Send for AppState {}
unsafe impl Sync for AppState {}

#[derive(Clone)]
struct ServerContext {
    state: Arc<std::sync::Mutex<AppState>>,
    expected_auth: Option<Arc<str>>,
}

/// Creates the worker HTTP router. **Must** be served on a single-threaded
/// tokio runtime (`Builder::new_current_thread()`) because GPU device
/// pointers are !Send.
pub fn create_router(secret: Option<String>) -> Router {
    debug_assert!(
        tokio::runtime::Handle::try_current()
            .map(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread)
            .unwrap_or(true),
        "create_router must be called on a current_thread runtime (GPU state is !Send)"
    );

    let ctx = ServerContext {
        state: Arc::new(std::sync::Mutex::new(AppState {
            proving_since: None,
        })),
        expected_auth: secret.map(|s| Arc::from(format!("Bearer {}", s))),
    };

    Router::new()
        .route("/health", get(health_handler))
        .route("/prove", post(prove_handler))
        .route("/prove/root", post(prove_root_handler))
        .route("/prove/halo2", post(prove_halo2_handler))
        .route("/halo2/preload", post(halo2_preload_handler))
        .route("/grind", post(grind_handler))
        .route("/release-gpu", post(release_gpu_handler))
        .layer(axum::extract::DefaultBodyLimit::max(256 * 1024 * 1024))
        .with_state(ctx)
}

fn require_auth(ctx: &ServerContext, headers: &HeaderMap) -> Option<axum::response::Response> {
    if let Some(ref expected) = ctx.expected_auth {
        match headers.get("authorization") {
            Some(v) if v.as_bytes() == expected.as_bytes() => None,
            _ => Some(
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "unauthorized".to_string(),
                        retryable: false,
                    }),
                )
                    .into_response(),
            ),
        }
    } else {
        None
    }
}

fn system_resources_summary() -> Option<String> {
    use std::sync::OnceLock;
    static GPU_VENDOR: OnceLock<Option<String>> = OnceLock::new();

    let mut parts = Vec::new();
    if let Some(v) = GPU_VENDOR.get_or_init(|| std::env::var("GPU_VENDOR").ok()) {
        parts.push(format!("gpu={}", v));
    }
    if let Ok(info) = sys_info::mem_info() {
        parts.push(format!("{:.1}GiB RAM", info.total as f64 / 1024.0 / 1024.0));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

// ─── Proving guard ──────────────────────────────────────────────────────────
//
// Every GPU-intensive handler follows the same lifecycle:
//   1. Mark worker busy (proving_since = now)
//   2. release_and_reinit_pool (pre-cleanup for max VRAM)
//   3. catch_unwind the proving closure
//   4. Mark worker idle
//   5. release_and_reinit_pool (post-cleanup)
//   6. Return serialized result or error
//
// `run_guarded` encapsulates steps 2-5 so handlers only provide the closure.

#[allow(clippy::result_large_err)]
fn try_acquire_busy(ctx: &ServerContext) -> Result<(), axum::response::Response> {
    let mut guard = ctx.state.lock().unwrap();
    if guard.proving_since.is_some() {
        Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "worker busy".to_string(),
                retryable: true,
            }),
        )
            .into_response())
    } else {
        guard.proving_since = Some(std::time::Instant::now());
        Ok(())
    }
}

fn run_guarded<T>(ctx: &ServerContext, f: impl FnOnce() -> eyre::Result<T>) -> Result<T, String> {
    // Pre-cleanup: reclaim any residual GPU pages so proving starts with
    // maximum available VRAM. Without this, marginal circuits can OOM on
    // the first attempt due to leftover pool allocations.
    crate::release_and_reinit_pool();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));

    {
        let mut guard = ctx.state.lock().unwrap();
        guard.proving_since = None;
    }

    crate::release_and_reinit_pool();

    match result {
        Ok(Ok(val)) => Ok(val),
        Ok(Err(e)) => Err(format!("{}", e)),
        Err(panic_info) => {
            let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            error!("GPU task panicked: {}", msg);
            Err(format!("panicked: {}", msg))
        }
    }
}

fn is_retryable_error(err: &str) -> bool {
    err.contains("out of memory")
        || err.contains("OOM")
        || err.contains("OutOfMemory")
        || err.contains("hipErrorOutOfMemory")
        || err.contains("CUDA_ERROR_OUT_OF_MEMORY")
}

fn error_response(err: String, retryable: bool) -> axum::response::Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: err,
            retryable,
        }),
    )
        .into_response()
}

fn bitcode_ok_response(body: Vec<u8>) -> axum::response::Response {
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        body,
    )
        .into_response()
}

// ─── Handlers ───────────────────────────────────────────────────────────────

async fn health_handler(State(ctx): State<ServerContext>) -> impl IntoResponse {
    let proving_elapsed = {
        let guard = ctx.state.lock().unwrap();
        guard.proving_since.map(|t| t.elapsed())
    };

    let status_str = match proving_elapsed {
        Some(elapsed) => format!("proving ({:.1}s)", elapsed.as_secs_f64()),
        None => "available".to_string(),
    };

    let gpu_info = {
        let mut parts = Vec::new();
        #[cfg(feature = "cuda")]
        {
            let (free, total) = openvm_cuda_common::memory_manager::gpu_memory_info();
            parts.push(format!(
                "gpu={:.1}/{:.1}GiB free",
                free as f64 / (1 << 30) as f64,
                total as f64 / (1 << 30) as f64
            ));
        }
        if let Some(sys) = system_resources_summary() {
            parts.push(sys);
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(", "))
        }
    };

    Json(crate::types::HealthResponse {
        status: status_str,
        ready: proving_elapsed.is_none(),
        gpu_info,
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    })
}

/// Unified prove endpoint: receives all context (PK, ELF, stdin, segments)
/// in a single request. Worker builds state, proves, drops everything.
async fn prove_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if let Some(resp) = require_auth(&ctx, &headers) {
        return resp;
    }

    if let Err(resp) = try_acquire_busy(&ctx) {
        return resp;
    }

    info!("Received /prove request ({} bytes)", body.len());

    let request: crate::types::ProveRequest = match bitcode::deserialize(&body) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to parse prove request: {}", e);
            let mut guard = ctx.state.lock().unwrap();
            guard.proving_since = None;
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("invalid payload: {}", e),
                    retryable: false,
                }),
            )
                .into_response();
        }
    };

    match run_guarded(&ctx, || crate::worker::prove_from_request(request)) {
        Ok(response) => {
            info!(
                "{} proofs, {:.1}s",
                response.proof_bytes.len(),
                response.proving_time_ms as f64 / 1000.0
            );
            match bitcode::serialize(&response) {
                Ok(body) => bitcode_ok_response(body),
                Err(e) => error_response(format!("serialization failed: {}", e), false),
            }
        }
        Err(e) => {
            error!("Proving failed: {}", e);
            error_response(format!("proving failed: {}", e), is_retryable_error(&e))
        }
    }
}

#[cfg(feature = "cuda")]
async fn prove_root_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    if let Some(resp) = require_auth(&ctx, &headers) {
        return resp;
    }

    if let Err(resp) = try_acquire_busy(&ctx) {
        return resp;
    }

    info!("Received prove/root request ({} bytes)", body.len());

    let task: crate::types::RootProveTask = match bitcode::deserialize(&body) {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to parse root prove task: {}", e);
            let mut guard = ctx.state.lock().unwrap();
            guard.proving_since = None;
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("invalid root task: {}", e),
                    retryable: false,
                }),
            )
                .into_response();
        }
    };

    let start = std::time::Instant::now();

    match run_guarded(&ctx, || crate::worker::prove_root_standalone(&task)) {
        Ok(mut response) => {
            response.proving_time_ms = start.elapsed().as_millis() as u64;
            info!(
                "Root proving done in {}ms, proof={} bytes",
                response.proving_time_ms,
                response.root_proof_bytes.len()
            );
            match bitcode::serialize(&response) {
                Ok(body) => bitcode_ok_response(body),
                Err(e) => error_response(format!("serialization failed: {}", e), false),
            }
        }
        Err(e) => {
            error!("Root proving failed: {}", e);
            error_response(
                format!("root proving failed: {}", e),
                is_retryable_error(&e),
            )
        }
    }
}

#[cfg(not(feature = "cuda"))]
async fn prove_root_handler(
    State(_ctx): State<ServerContext>,
    _headers: HeaderMap,
    _body: axum::body::Bytes,
) -> impl IntoResponse {
    error_response(
        "root proving requires the `cuda` feature".to_string(),
        false,
    )
}

async fn prove_halo2_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    if let Some(resp) = require_auth(&ctx, &headers) {
        return resp;
    }

    if let Err(resp) = try_acquire_busy(&ctx) {
        return resp;
    }

    info!("Received prove/halo2 request ({} bytes)", body.len());

    let task: crate::types::Halo2ProveTask = match serde_json::from_slice(&body) {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to parse halo2 prove task: {}", e);
            let mut guard = ctx.state.lock().unwrap();
            guard.proving_since = None;
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("invalid halo2 task: {}", e),
                    retryable: false,
                }),
            )
                .into_response();
        }
    };

    let start = std::time::Instant::now();

    match run_guarded(&ctx, || crate::worker::prove_halo2_inline(&task)) {
        Ok(mut response) => {
            response.proving_time_ms = start.elapsed().as_millis() as u64;
            info!(
                "Halo2 proving done in {}ms",
                response.proving_time_ms
            );
            match bitcode::serialize(&response) {
                Ok(body) => bitcode_ok_response(body),
                Err(e) => error_response(format!("serialization failed: {}", e), false),
            }
        }
        Err(e) => {
            error!("Halo2 proving failed: {}", e);
            error_response(
                format!("halo2 proving failed: {}", e),
                is_retryable_error(&e),
            )
        }
    }
}

async fn halo2_preload_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Json(req): Json<crate::types::Halo2PreloadRequest>,
) -> impl IntoResponse {
    if let Some(resp) = require_auth(&ctx, &headers) {
        return resp;
    }

    let start = std::time::Instant::now();
    let pk_path = std::path::Path::new(&req.halo2_pk_path);
    let kzg_ready = req
        .kzg_params_dir
        .as_ref()
        .is_none_or(|d| std::path::Path::new(d).is_dir());

    let pk_exists = pk_path.exists();
    let ready = pk_exists && kzg_ready;

    let load_time_ms = start.elapsed().as_millis() as u64;

    if ready {
        info!(
            "Halo2 preload OK: pk={:?} ({:.1} GB), kzg=ready",
            pk_path,
            pk_path
                .metadata()
                .map(|m| m.len() as f64 / 1e9)
                .unwrap_or(0.0)
        );
    } else {
        error!(
            "Halo2 preload FAILED: pk_exists={}, kzg_ready={}",
            pk_exists, kzg_ready
        );
    }

    Json(crate::types::Halo2PreloadResponse {
        ready,
        load_time_ms,
    })
    .into_response()
}

async fn release_gpu_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(resp) = require_auth(&ctx, &headers) {
        return resp;
    }

    crate::release_and_reinit_pool();
    info!("GPU released");

    (StatusCode::OK, Json(serde_json::json!({"released": true}))).into_response()
}

#[cfg(feature = "cuda")]
async fn grind_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Json(req): Json<crate::types::GrindRequest>,
) -> impl IntoResponse {
    if let Some(resp) = require_auth(&ctx, &headers) {
        return resp;
    }

    if let Err(resp) = try_acquire_busy(&ctx) {
        return resp;
    }

    let start = std::time::Instant::now();
    let witness = match run_guarded(&ctx, || crate::worker::run_grind_kernel(&req)) {
        Ok(w) => w,
        Err(e) => {
            error!("Grind failed: {}", e);
            None
        }
    };

    Json(crate::types::GrindResponse {
        witness,
        grind_time_ms: start.elapsed().as_millis() as u64,
    })
    .into_response()
}

#[cfg(not(feature = "cuda"))]
async fn grind_handler(
    State(_ctx): State<ServerContext>,
    _headers: HeaderMap,
    Json(_req): Json<crate::types::GrindRequest>,
) -> impl IntoResponse {
    Json(crate::types::GrindResponse {
        witness: None,
        grind_time_ms: 0,
    })
}
