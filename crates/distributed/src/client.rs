use std::time::Duration;

use eyre::{bail, Context, Result};
use reqwest::Client;
use tracing::{error, warn};

use crate::types::{ErrorResponse, HealthResponse, ProveSegmentsResponse};

const MAX_RETRIES: u32 = 2;
const TASK_TIMEOUT: Duration = Duration::from_secs(3600);

#[derive(Clone)]
pub struct WorkerClient {
    client: Client,
    base_url: String,
    secret: Option<String>,
}

impl WorkerClient {
    pub fn new(base_url: &str, secret: Option<String>) -> Result<Self> {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(7200))
            .tcp_keepalive(Duration::from_secs(30))
            .pool_max_idle_per_host(4)
            .build()
            .wrap_err("failed to build HTTP client")?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            secret,
        })
    }

    fn estimated_timeout_for(num_segments: usize) -> Duration {
        const PER_SEGMENT: Duration = Duration::from_secs(180);
        const OVERHEAD: Duration = Duration::from_secs(120);
        std::cmp::min(OVERHEAD + PER_SEGMENT * num_segments as u32, TASK_TIMEOUT)
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn authed_post(&self, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.client.post(url);
        if let Some(ref secret) = self.secret {
            req = req.header("authorization", format!("Bearer {}", secret));
        }
        req
    }

    pub async fn health(&self) -> Result<HealthResponse> {
        let url = format!("{}/health", self.base_url);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .wrap_err("health check failed")?;
        let health: HealthResponse = resp.json().await?;
        Ok(health)
    }

    pub async fn release_gpu(&self) -> Result<bool> {
        let resp = self
            .authed_post("/release-gpu")
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .wrap_err("release-gpu request failed")?;
        if !resp.status().is_success() {
            bail!("release-gpu failed with status {}", resp.status());
        }
        let body: serde_json::Value = resp.json().await?;
        Ok(body
            .get("released")
            .and_then(|v| v.as_bool())
            .unwrap_or(false))
    }

    pub async fn grind(
        &self,
        request: &crate::types::GrindRequest,
    ) -> Result<crate::types::GrindResponse> {
        let resp = self
            .authed_post("/grind")
            .json(request)
            .timeout(Duration::from_secs(300))
            .send()
            .await
            .wrap_err("grind request failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            bail!("grind failed with status {}: {}", status, body_text);
        }
        let grind_resp: crate::types::GrindResponse = resp.json().await?;
        Ok(grind_resp)
    }

    /// Unified prove: sends PK, ELF, stdin, and segment descriptors in one
    /// request. Worker builds state, proves, drops everything. Retries on
    /// transient errors.
    pub async fn prove(
        &self,
        request_bytes: &[u8],
        num_segments: usize,
    ) -> Result<ProveSegmentsResponse> {
        let timeout = Self::estimated_timeout_for(num_segments);

        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                warn!(
                    "Retrying prove (attempt {}/{})",
                    attempt + 1,
                    MAX_RETRIES + 1
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
            }

            let req = self
                .authed_post("/prove")
                .body(Vec::from(request_bytes))
                .header("content-type", "application/octet-stream")
                .timeout(timeout);

            match req.send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        let bytes = resp
                            .bytes()
                            .await
                            .wrap_err("failed to read prove response body")?;
                        let prove_resp: ProveSegmentsResponse = bitcode::deserialize(&bytes)
                            .wrap_err("failed to deserialize prove response")?;
                        return Ok(prove_resp);
                    }

                    let status = resp.status();
                    let body_text = resp.text().await.unwrap_or_default();

                    if let Ok(err_resp) = serde_json::from_str::<ErrorResponse>(&body_text) {
                        if !err_resp.retryable {
                            bail!("non-retryable error from worker: {}", err_resp.error);
                        }
                        error!("Retryable error from worker: {}", err_resp.error);
                    } else if status.as_u16() == 400 || status.as_u16() == 401 {
                        bail!("non-retryable HTTP {}: {}", status, body_text);
                    } else {
                        error!("Worker returned status {}: {}", status, body_text);
                    }
                }
                Err(e) => {
                    if e.is_timeout() {
                        error!(
                            "Request timed out after {:?} ({} segments)",
                            timeout, num_segments
                        );
                    } else if e.is_connect() {
                        error!("Connection refused to {}: {}", self.base_url, e);
                    } else {
                        error!("Request failed: {}", e);
                    }
                    if attempt == MAX_RETRIES {
                        bail!("prove failed after {} attempts: {}", attempt + 1, e);
                    }
                }
            }
        }

        bail!(
            "prove failed: retryable errors on all {} attempts",
            MAX_RETRIES + 1
        )
    }

    pub async fn prove_root(
        &self,
        task: &crate::types::RootProveTask,
    ) -> Result<crate::types::RootProveResponse> {
        let body = bitcode::serialize(task).wrap_err("failed to serialize RootProveTask")?;
        let timeout = Duration::from_secs(120);

        let resp = self
            .authed_post("/prove/root")
            .body(body)
            .header("content-type", "application/octet-stream")
            .timeout(timeout)
            .send()
            .await
            .wrap_err("prove_root request failed")?;

        if resp.status().is_success() {
            let bytes = resp
                .bytes()
                .await
                .wrap_err("failed to read root prove response")?;
            let root_resp: crate::types::RootProveResponse = bitcode::deserialize(&bytes)
                .wrap_err("failed to deserialize root prove response")?;
            Ok(root_resp)
        } else {
            let body_text = resp.text().await.unwrap_or_default();
            bail!("prove_root failed: {}", body_text)
        }
    }

    pub async fn halo2_preload(
        &self,
        request: &crate::types::Halo2PreloadRequest,
    ) -> Result<crate::types::Halo2PreloadResponse> {
        let resp = self
            .authed_post("/halo2/preload")
            .json(request)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .wrap_err("halo2 preload request failed")?;
        if !resp.status().is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            bail!("halo2 preload failed: {}", body_text);
        }
        Ok(resp.json().await?)
    }

    pub async fn prove_halo2(
        &self,
        task: &crate::types::Halo2ProveTask,
    ) -> Result<crate::types::Halo2ProveResponse> {
        let body = serde_json::to_vec(task).wrap_err("failed to serialize Halo2ProveTask")?;
        let timeout = Duration::from_secs(90);

        let resp = self
            .authed_post("/prove/halo2")
            .body(body)
            .header("content-type", "application/json")
            .timeout(timeout)
            .send()
            .await
            .wrap_err("prove_halo2 request failed")?;

        if resp.status().is_success() {
            let bytes = resp
                .bytes()
                .await
                .wrap_err("failed to read halo2 prove response")?;
            let halo2_resp: crate::types::Halo2ProveResponse = bitcode::deserialize(&bytes)
                .wrap_err("failed to deserialize halo2 prove response")?;
            Ok(halo2_resp)
        } else {
            let body_text = resp.text().await.unwrap_or_default();
            bail!("prove_halo2 failed: {}", body_text)
        }
    }
}
