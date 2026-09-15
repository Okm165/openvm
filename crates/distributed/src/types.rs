use serde::{Deserialize, Serialize};

/// Self-contained proving request. Carries all context the worker needs.
/// The orchestrator builds one per worker, sends in parallel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveRequest {
    pub app_pk_bytes: Vec<u8>,
    pub exe_bytes: Vec<u8>,
    pub stdin_bytes: Vec<u8>,
    pub segments: Vec<SegmentDescriptor>,
    pub compute_user_public_values: bool,
    pub aggregate_to_leaf: bool,
    pub num_children_leaf: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentDescriptor {
    pub instret_start: u64,
    pub num_insns: u64,
    pub trace_heights: Vec<u32>,
}

impl From<&openvm_circuit::arch::execution_mode::Segment> for SegmentDescriptor {
    fn from(seg: &openvm_circuit::arch::execution_mode::Segment) -> Self {
        Self {
            instret_start: seg.instret_start,
            num_insns: seg.num_insns,
            trace_heights: seg.trace_heights.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveSegmentsResponse {
    pub proof_bytes: Vec<Vec<u8>>,
    pub user_public_values_bytes: Option<Vec<u8>>,
    pub proving_time_ms: u64,
    #[serde(default)]
    pub is_leaf_proofs: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub ready: bool,
    pub gpu_info: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrindRequest {
    pub sponge_state_bytes: Vec<u8>,
    pub bits: u32,
    pub min_witness: u32,
    pub max_witness: u32,
    #[serde(default = "default_witness_step")]
    pub witness_step: u32,
}

fn default_witness_step() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrindResponse {
    pub witness: Option<u32>,
    pub grind_time_ms: u64,
}

// ─── Root proving ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootProveTask {
    pub proof_bytes: Vec<u8>,
    pub metadata_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootProveResponse {
    pub root_proof_bytes: Vec<u8>,
    pub proving_time_ms: u64,
}

// ─── Halo2 proving ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Halo2PreloadRequest {
    pub halo2_pk_path: String,
    pub kzg_params_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Halo2PreloadResponse {
    pub ready: bool,
    pub load_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Halo2ProveTask {
    pub root_proof_bytes: Vec<u8>,
    pub halo2_pk_path: String,
    pub kzg_params_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Halo2ProveResponse {
    pub proving_time_ms: u64,
    /// Serialized EvmProof JSON returned by the worker after Halo2 proving.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evm_proof_json: Option<String>,
}
