pub(crate) mod assignment;
pub mod client;
#[cfg(feature = "evm")]
pub mod evm;
pub mod orchestrator;
pub mod server;
pub mod types;
pub(crate) mod worker;

use tracing::info;

pub fn log_system_memory() {
    if let Ok(mem) = sys_info::mem_info() {
        info!(
            "System memory: {:.1} GiB total, {:.1} GiB available",
            mem.total as f64 / 1024.0 / 1024.0,
            mem.avail as f64 / 1024.0 / 1024.0
        );
    }
}

#[inline]
pub fn release_cuda_memory() {
    #[cfg(feature = "cuda")]
    {
        openvm_cuda_common::memory_manager::release_free_pages();
        openvm_cuda_common::stream::device_synchronize().ok();
    }
}
