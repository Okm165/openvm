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

use crate::{
    types::{
        ErrorResponse, HealthResponse, SegmentTask, SetupCheckRequest, SetupCheckResponse,
        SetupPayload, SetupResponse,
    },
    worker::{CachedConfig, WorkerState},
};

struct AppState {
    worker: Option<WorkerState>,
    cached_config: Option<CachedConfig>,
    proving_since: Option<std::time::Instant>,
    setup_fingerprint: Option<u64>,
}

// SAFETY: WorkerState holds GPU device pointers that are inherently !Send/!Sync.
// This is sound because the worker binary uses a single-threaded tokio runtime
// (Builder::new_current_thread()), so AppState never actually crosses thread boundaries.
// Callers MUST NOT use create_router() with a multi-threaded runtime.
unsafe impl Send for AppState {}
unsafe impl Sync for AppState {}

#[derive(Clone)]
struct ServerContext {
    state: Arc<std::sync::Mutex<AppState>>,
    /// Pre-computed "Bearer {secret}" string, or None if auth is disabled.
    expected_auth: Option<Arc<str>>,
}

/// Creates the worker HTTP router. **Must** be served on a single-threaded
/// tokio runtime (`Builder::new_current_thread()`) because `WorkerState` holds
/// GPU device pointers that are !Send.
pub fn create_router(secret: Option<String>) -> Router {
    debug_assert!(
        tokio::runtime::Handle::try_current()
            .map(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread)
            .unwrap_or(true),
        "create_router must be called on a current_thread runtime (GPU state is !Send)"
    );

    let ctx = ServerContext {
        state: Arc::new(std::sync::Mutex::new(AppState {
            worker: None,
            cached_config: None,
            proving_since: None,
            setup_fingerprint: None,
        })),
        expected_auth: secret.map(|s| Arc::from(format!("Bearer {}", s))),
    };

    Router::new()
        .route("/health", get(health_handler))
        .route("/setup", post(setup_handler))
        .route("/setup/check", post(setup_check_handler))
        .route("/prove/segments", post(prove_segments_handler))
        .route("/grind", post(grind_handler))
        .route("/release-gpu", post(release_gpu_handler))
        .route("/shutdown", post(shutdown_handler))
        .layer(axum::extract::DefaultBodyLimit::max(256 * 1024 * 1024))
        .with_state(ctx)
}

fn check_auth(expected_auth: &Option<Arc<str>>, headers: &HeaderMap) -> Result<(), StatusCode> {
    if let Some(ref expected) = expected_auth {
        match headers.get("authorization") {
            Some(v) if v.as_bytes() == expected.as_bytes() => Ok(()),
            _ => Err(StatusCode::UNAUTHORIZED),
        }
    } else {
        Ok(())
    }
}

fn require_auth(ctx: &ServerContext, headers: &HeaderMap) -> Option<axum::response::Response> {
    if let Err(status) = check_auth(&ctx.expected_auth, headers) {
        Some(
            (
                status,
                Json(ErrorResponse {
                    error: "unauthorized".to_string(),
                    retryable: false,
                }),
            )
                .into_response(),
        )
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

async fn health_handler(State(ctx): State<ServerContext>) -> impl IntoResponse {
    let (ready, proving_elapsed) = {
        let guard = ctx.state.lock().unwrap();
        let ready = guard.worker.is_some();
        let elapsed = guard.proving_since.map(|t| t.elapsed());
        (ready, elapsed)
    };

    let status_str = if let Some(elapsed) = proving_elapsed {
        format!("proving ({:.1}s)", elapsed.as_secs_f64())
    } else if ready {
        "idle".to_string()
    } else {
        "not_configured".to_string()
    };

    let mem_info = system_resources_summary();

    Json(HealthResponse {
        status: status_str,
        ready: ready && proving_elapsed.is_none(),
        gpu_info: mem_info,
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    })
}

type SharedState = Arc<std::sync::Mutex<AppState>>;

fn try_warm_resetup(state: &SharedState, fingerprint: u64) -> bool {
    let cached = {
        let mut guard = state.lock().unwrap();
        if guard.setup_fingerprint != Some(fingerprint) {
            return false;
        }
        guard.worker = None;
        guard.cached_config.take()
    };

    let Some(cached) = cached else { return false };

    match WorkerState::from_cached(cached) {
        Ok(worker) => {
            state.lock().unwrap().worker = Some(worker);
            true
        }
        Err(e) => {
            error!("Warm re-setup failed: {:?}", e);
            let mut guard = state.lock().unwrap();
            guard.setup_fingerprint = None;
            false
        }
    }
}

async fn setup_check_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    Json(req): Json<SetupCheckRequest>,
) -> impl IntoResponse {
    if let Some(resp) = require_auth(&ctx, &headers) {
        return resp;
    }

    {
        let guard = ctx.state.lock().unwrap();
        if guard.worker.is_some() && guard.setup_fingerprint == Some(req.fingerprint) {
            return Json(SetupCheckResponse {
                needs_payload: false,
            })
            .into_response();
        }
    }

    let needs_payload = !try_warm_resetup(&ctx.state, req.fingerprint);
    Json(SetupCheckResponse { needs_payload }).into_response()
}

async fn setup_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if let Some(resp) = require_auth(&ctx, &headers) {
        return resp;
    }
    {
        let guard = ctx.state.lock().unwrap();
        if guard.proving_since.is_some() {
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "cannot setup while proving is in progress".to_string(),
                    retryable: true,
                }),
            )
                .into_response();
        }
    }

    info!("Received setup payload ({} bytes)", body.len());

    let fingerprint = crate::types::SetupPayload::content_fingerprint(&body);
    {
        let guard = ctx.state.lock().unwrap();
        if guard.worker.is_some() && guard.setup_fingerprint == Some(fingerprint) {
            return (
                StatusCode::OK,
                Json(SetupResponse {
                    message: "Setup unchanged (cached), worker ready".to_string(),
                }),
            )
                .into_response();
        }
    }

    if try_warm_resetup(&ctx.state, fingerprint) {
        return (
            StatusCode::OK,
            Json(SetupResponse {
                message: "Warm re-setup complete (cached config), worker ready".to_string(),
            }),
        )
            .into_response();
    }

    let payload: SetupPayload = match bitcode::deserialize(&body) {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to parse setup payload: {}", e);
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

    {
        let mut guard = ctx.state.lock().unwrap();
        guard.worker = None;
    }

    match WorkerState::from_setup(payload) {
        Ok(worker) => {
            let mut guard = ctx.state.lock().unwrap();
            guard.worker = Some(worker);
            guard.setup_fingerprint = Some(fingerprint);
            (
                StatusCode::OK,
                Json(SetupResponse {
                    message: "Setup complete, worker ready".to_string(),
                }),
            )
                .into_response()
        }
        Err(e) => {
            error!("Worker setup failed: {:?}", e);
            let mut guard = ctx.state.lock().unwrap();
            guard.setup_fingerprint = None;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("setup failed: {}", e),
                    retryable: true,
                }),
            )
                .into_response()
        }
    }
}

async fn prove_segments_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if let Some(resp) = require_auth(&ctx, &headers) {
        return resp;
    }

    info!("Received prove/segments request ({} bytes)", body.len());

    let task: SegmentTask = match serde_json::from_slice(&body) {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to parse segment task: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("invalid task: {}", e),
                    retryable: false,
                }),
            )
                .into_response();
        }
    };

    let worker = {
        let mut guard = ctx.state.lock().unwrap();
        guard.proving_since = Some(std::time::Instant::now());
        match guard.worker.take() {
            Some(w) => w,
            None => {
                // Attempt warm re-setup from cached config (handles retry after OOM/failure)
                if let Some(cached) = guard.cached_config.take() {
                    drop(guard);
                    match WorkerState::from_cached(cached) {
                        Ok(w) => w,
                        Err(e) => {
                            error!("Warm re-setup for retry failed: {:?}", e);
                            let mut guard = ctx.state.lock().unwrap();
                            guard.proving_since = None;
                            return (
                                StatusCode::SERVICE_UNAVAILABLE,
                                Json(ErrorResponse {
                                    error: "worker not ready and re-setup failed".to_string(),
                                    retryable: false,
                                }),
                            )
                                .into_response();
                        }
                    }
                } else {
                    guard.proving_since = None;
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(ErrorResponse {
                            error: "worker not ready (call /setup first)".to_string(),
                            retryable: true,
                        }),
                    )
                        .into_response();
                }
            }
        }
    };

    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| worker.prove_segments(task)));

    let (result, cached_config) = match result {
        Ok((r, cached)) => (r, Some(cached)),
        Err(panic_info) => {
            let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            error!("Proving panicked: {}", msg);
            (Err(eyre::eyre!("proving panicked: {}", msg)), None)
        }
    };

    {
        let mut guard = ctx.state.lock().unwrap();
        guard.proving_since = None;
        if let Some(cached) = cached_config {
            guard.cached_config = Some(cached);
        }
    }

    match result {
        Ok(response) => {
            info!(
                "{} proofs, {:.1}s",
                response.proof_bytes.len(),
                response.proving_time_ms as f64 / 1000.0
            );
            match bitcode::serialize(&response) {
                Ok(body) => (
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                    body,
                )
                    .into_response(),
                Err(e) => {
                    error!("Failed to serialize prove response: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: format!("serialization failed: {}", e),
                            retryable: false,
                        }),
                    )
                        .into_response()
                }
            }
        }
        Err(e) => {
            error!("Segment proving failed: {:?}", e);
            let err_str = format!("{}", e);
            let retryable = err_str.contains("out of memory")
                || err_str.contains("OOM")
                || err_str.contains("device lost");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("proving failed: {}", e),
                    retryable,
                }),
            )
                .into_response()
        }
    }
}

async fn release_gpu_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(resp) = require_auth(&ctx, &headers) {
        return resp;
    }

    let had_state = {
        let mut guard = ctx.state.lock().unwrap();
        let had = guard.worker.is_some() || guard.cached_config.is_some();
        guard.worker = None;
        guard.cached_config = None;
        guard.setup_fingerprint = None;
        had
    };

    crate::release_cuda_memory();
    info!("GPU released (had_state={})", had_state);

    (
        StatusCode::OK,
        Json(serde_json::json!({"released": had_state})),
    )
        .into_response()
}

async fn shutdown_handler(
    State(ctx): State<ServerContext>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(resp) = require_auth(&ctx, &headers) {
        return resp;
    }
    info!("Shutdown requested — exiting process to release all GPU memory");
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        std::process::exit(0);
    });
    (
        StatusCode::OK,
        Json(serde_json::json!({"shutting_down": true})),
    )
        .into_response()
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

    info!(
        "Grind request: bits={}, range=[{}, {}]",
        req.bits, req.min_witness, req.max_witness
    );
    let start = std::time::Instant::now();

    let witness = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::worker::run_grind_kernel(&req)
    }))
    .unwrap_or_else(|_| {
        error!("Grind kernel panicked");
        Ok(None)
    })
    .unwrap_or_else(|e| {
        error!("Grind kernel error: {:?}", e);
        None
    });

    let grind_time_ms = start.elapsed().as_millis() as u64;
    info!(
        "Grind complete: witness={:?} in {}ms",
        witness, grind_time_ms
    );
    Json(crate::types::GrindResponse {
        witness,
        grind_time_ms,
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
