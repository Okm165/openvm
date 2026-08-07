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

/// Lightweight GPU memory release: sync device, return free VPMM pages
/// to the driver. Safe to call after any proving stage. Does not destroy
/// pool state — the next allocation can re-map pages on demand.
#[inline]
pub fn release_cuda_memory() {
    #[cfg(feature = "cuda")]
    {
        openvm_cuda_common::stream::device_synchronize().ok();
        openvm_cuda_common::memory_manager::force_release_free_pages();
    }
}

/// Heavy GPU memory release: free all tracked small allocations, drop the
/// entire VPMM pool (unmaps pages, releases physical memory, frees VA
/// reservations), and create a fresh pool with new VAs.
///
/// The fresh pool gets completely new VAs from `vpmm_reserve()`, so there
/// is no VA reuse and no AMD RDNA L1 cache coherence concern. Does NOT
/// call `hipDeviceReset()` — that would invalidate GPU state held by
/// other libraries (e.g. halo2-gpu kernel modules).
///
/// Use before/after Halo2 transitions, or when the orchestrator is done
/// with GPU work and wants to maximize VRAM for co-located workers.
#[inline]
pub fn release_and_reinit_pool() {
    #[cfg(feature = "cuda")]
    {
        openvm_cuda_common::memory_manager::release_and_reinit_pool();
    }
}
