use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupPayload {
    pub app_pk_bytes: Vec<u8>,
    pub exe_bytes: Vec<u8>,
    pub stdin_bytes: Vec<u8>,
}

impl SetupPayload {
    /// FNV-1a fingerprint for cache invalidation.
    pub fn content_fingerprint(raw_bytes: &[u8]) -> u64 {
        const FNV_OFFSET: u64 = 0xcbf29ce484222325;
        const FNV_PRIME: u64 = 0x100000001b3;
        let mut hash = FNV_OFFSET;
        for &byte in raw_bytes {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentTask {
    pub segments: Vec<SegmentDescriptor>,
    #[serde(default)]
    pub compute_user_public_values: bool,
    #[serde(default)]
    pub aggregate_to_leaf: bool,
    #[serde(default = "default_num_children_leaf")]
    pub num_children_leaf: usize,
}

fn default_num_children_leaf() -> usize {
    4
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
pub struct SetupResponse {
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupCheckRequest {
    pub fingerprint: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupCheckResponse {
    pub needs_payload: bool,
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
