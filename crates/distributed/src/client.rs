use std::time::Duration;

use eyre::{bail, Context, Result};
use reqwest::Client;
use tracing::{error, info, warn};

use crate::types::{
    ErrorResponse, HealthResponse, ProveSegmentsResponse, SegmentTask, SetupCheckRequest,
    SetupCheckResponse, SetupPayload, SetupResponse,
};

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

    pub fn is_local(&self) -> bool {
        self.base_url.contains("localhost") || self.base_url.contains("127.0.0.1")
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

    pub async fn shutdown(&self) -> Result<()> {
        match self
            .authed_post("/shutdown")
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(e) if e.is_connect() || e.is_timeout() => Ok(()),
            Err(e) => Err(eyre::eyre!("shutdown request failed: {}", e)),
        }
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

    pub async fn setup_with_bytes(&self, payload_bytes: &[u8]) -> Result<SetupResponse> {
        let fingerprint = SetupPayload::content_fingerprint(payload_bytes);

        if let Ok(check) = self.setup_check(fingerprint).await {
            if !check.needs_payload {
                return Ok(SetupResponse {
                    message: "cached".to_string(),
                });
            }
        }

        info!("Sending {} bytes to {}", payload_bytes.len(), self.base_url);

        let resp = self
            .authed_post("/setup")
            .body(Vec::from(payload_bytes))
            .header("content-type", "application/octet-stream")
            .timeout(Duration::from_secs(60))
            .send()
            .await
            .wrap_err("setup request failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("setup failed with status {}: {}", status, body);
        }

        Ok(resp.json().await?)
    }

    async fn setup_check(&self, fingerprint: u64) -> Result<SetupCheckResponse> {
        let resp = self
            .authed_post("/setup/check")
            .json(&SetupCheckRequest { fingerprint })
            .timeout(Duration::from_secs(5))
            .send()
            .await?;
        Ok(resp.json().await?)
    }

    pub async fn prove_segments(&self, task: &SegmentTask) -> Result<ProveSegmentsResponse> {
        let body = serde_json::to_vec(task)?;
        let timeout = Self::estimated_timeout_for(task.segments.len());

        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                warn!(
                    "Retrying prove_segments (attempt {}/{})",
                    attempt + 1,
                    MAX_RETRIES + 1
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
            }

            let req = self
                .authed_post("/prove/segments")
                .body(body.clone())
                .header("content-type", "application/json")
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
                    } else {
                        error!("Worker returned status {}: {}", status, body_text);
                    }
                }
                Err(e) => {
                    if e.is_timeout() {
                        error!(
                            "Request timed out after {:?} ({} segments). Worker may be overloaded or unreachable.",
                            timeout, task.segments.len()
                        );
                    } else if e.is_connect() {
                        error!(
                            "Connection refused/failed to {}: {}. Is the worker running?",
                            self.base_url, e
                        );
                    } else {
                        error!("Request failed: {}", e);
                    }
                    if attempt == MAX_RETRIES {
                        bail!(
                            "prove_segments failed after {} attempts: {}",
                            attempt + 1,
                            e
                        );
                    }
                }
            }
        }

        bail!(
            "prove_segments failed: retryable errors on all {} attempts",
            MAX_RETRIES + 1
        )
    }
}
