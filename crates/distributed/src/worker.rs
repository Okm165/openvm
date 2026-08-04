use std::{sync::Arc, time::Instant};

use eyre::{Context, Result};
use openvm_circuit::{
    arch::{
        hasher::poseidon2::vm_poseidon2_hasher, instructions::exe::VmExe, PreflightExecutionOutput,
        VmInstance,
    },
    system::memory::{merkle::public_values::UserPublicValuesProof, CHUNK},
};
use openvm_sdk::{
    config::AggregationSystemParams, keygen::AppProvingKey, prover::vm::new_local_prover,
    DefaultStarkEngine, Sdk, StdIn, F, SC,
};
use openvm_sdk_config::{SdkVmBuilder, SdkVmConfig};
use openvm_stark_backend::{codec::Encode, proof::Proof, StarkEngine};
use tracing::{info, info_span, instrument};

use crate::types::{ProveSegmentsResponse, SegmentDescriptor, SegmentTask, SetupPayload};

fn prove_segment(
    instance: &mut VmInstance<DefaultStarkEngine, SdkVmBuilder>,
    num_insns: u64,
    trace_heights: &[u32],
) -> Result<Proof<SC>> {
    let from_state = instance
        .state_mut()
        .take()
        .ok_or_else(|| eyre::eyre!("VM state not set before proving segment"))?;
    instance
        .vm
        .transport_init_memory_to_device(&from_state.memory);

    let PreflightExecutionOutput {
        system_records,
        record_arenas,
        to_state,
    } = instance.vm.execute_preflight(
        &mut instance.interpreter,
        from_state,
        Some(num_insns),
        trace_heights,
    )?;
    *instance.state_mut() = Some(to_state);

    let ctx = instance
        .vm
        .generate_proving_ctx(system_records, record_arenas)?;
    let engine = &instance.vm.engine;
    let pk = instance.vm.pk();
    Ok(engine.prove(pk, ctx)?)
}

fn extract_user_public_values(
    instance: &VmInstance<DefaultStarkEngine, SdkVmBuilder>,
) -> Result<UserPublicValuesProof<CHUNK, F>> {
    let memory_dimensions = instance
        .vm
        .config()
        .as_ref()
        .memory_config
        .memory_dimensions();
    let num_public_values = instance.vm.config().as_ref().num_public_values;
    let final_memory_top_tree: Vec<_> = instance
        .vm
        .memory_top_tree()
        .ok_or_else(|| eyre::eyre!(
            "memory_top_tree not populated — generate_proving_ctx must be called on the last segment"
        ))?
        .to_vec();

    let final_state = instance
        .state()
        .as_ref()
        .ok_or_else(|| eyre::eyre!("VM state not present — prove must complete first"))?;

    Ok(UserPublicValuesProof::compute(
        memory_dimensions,
        num_public_values,
        &vm_poseidon2_hasher(),
        &final_state.memory.memory,
        &final_memory_top_tree,
    ))
}

#[allow(clippy::type_complexity)]
fn recover_and_prove(
    mut instance: VmInstance<DefaultStarkEngine, SdkVmBuilder>,
    segments: &[SegmentDescriptor],
    sdk: &Sdk,
    exe: &Arc<VmExe<F>>,
    stdin: &StdIn<F>,
) -> Result<(Vec<Proof<SC>>, VmInstance<DefaultStarkEngine, SdkVmBuilder>)> {
    let first_instret = segments[0].instret_start;
    if first_instret > 0 {
        let _span = info_span!("e1_recovery", target = first_instret).entered();
        let e1_start = Instant::now();
        info!(
            "E1: re-executing {} instructions to reach segment start",
            first_instret
        );
        let e1_interp = sdk.executor().instance(exe)?;
        let recovered_state = e1_interp.execute(stdin.clone(), Some(first_instret))?;
        *instance.state_mut() = Some(recovered_state);
        info!("E1 recovery complete in {:?}", e1_start.elapsed());
    } else {
        instance.reset_state(stdin.clone());
    }

    let mut proofs = Vec::with_capacity(segments.len());
    for (i, seg) in segments.iter().enumerate() {
        let _span = info_span!("prove_segment", idx = i).entered();
        let seg_start = Instant::now();
        let proof = prove_segment(&mut instance, seg.num_insns, &seg.trace_heights)?;
        info!("Segment {} proved in {:?}", i, seg_start.elapsed());
        proofs.push(proof);
    }

    Ok((proofs, instance))
}

pub(crate) struct CachedConfig {
    sdk: Sdk,
    exe: Arc<VmExe<F>>,
    stdin: StdIn<F>,
}

pub(crate) struct WorkerState {
    instance: VmInstance<DefaultStarkEngine, SdkVmBuilder>,
    cached: CachedConfig,
}

impl WorkerState {
    #[instrument(name = "worker_setup", skip_all)]
    pub(crate) fn from_setup(payload: SetupPayload) -> Result<Self> {
        let start = Instant::now();
        info!(
            "Setup: pk={} B, exe={} B, stdin={} B",
            payload.app_pk_bytes.len(),
            payload.exe_bytes.len(),
            payload.stdin_bytes.len()
        );

        let app_pk: AppProvingKey<SdkVmConfig> =
            bitcode::deserialize(&payload.app_pk_bytes).wrap_err("deserialize app_pk")?;
        let exe: VmExe<F> = bitcode::deserialize(&payload.exe_bytes).wrap_err("deserialize exe")?;
        let stdin: StdIn<F> =
            bitcode::deserialize(&payload.stdin_bytes).wrap_err("deserialize stdin")?;

        let sdk = Sdk::builder()
            .app_pk(app_pk)
            .agg_params(AggregationSystemParams::default())
            .build()
            .wrap_err("build SDK from proving key")?;

        let exe = Arc::new(exe);
        let app_pk = sdk.app_pk();
        let instance = new_local_prover(*sdk.app_vm_builder(), &app_pk.app_vm_pk, exe.clone())
            .wrap_err("create VmInstance")?;

        info!("Setup complete in {:?}", start.elapsed());
        Ok(Self {
            instance,
            cached: CachedConfig { sdk, exe, stdin },
        })
    }

    #[instrument(name = "worker_warm_setup", skip_all)]
    pub(crate) fn from_cached(cached: CachedConfig) -> Result<Self> {
        let start = Instant::now();
        let app_pk = cached.sdk.app_pk();
        let instance = new_local_prover(
            *cached.sdk.app_vm_builder(),
            &app_pk.app_vm_pk,
            cached.exe.clone(),
        )
        .wrap_err("create VmInstance from cached config")?;
        info!("Warm re-setup in {:?}", start.elapsed());
        Ok(Self { instance, cached })
    }

    #[instrument(name = "worker_prove_segments", skip_all, fields(num_segments = task.segments.len()))]
    pub(crate) fn prove_segments(
        self,
        task: SegmentTask,
    ) -> (Result<ProveSegmentsResponse>, CachedConfig) {
        let total_start = Instant::now();
        let num_segments = task.segments.len();
        let Self { instance, cached } = self;

        if num_segments == 0 {
            return (Err(eyre::eyre!("received empty segment task")), cached);
        }

        // Validate segment descriptor contiguity (soundness check)
        for window in task.segments.windows(2) {
            if window[0].instret_start + window[0].num_insns != window[1].instret_start {
                return (Err(eyre::eyre!(
                    "Segment descriptors not contiguous: seg ending at instret {} + {} != next starting at {}",
                    window[0].instret_start, window[0].num_insns, window[1].instret_start
                )), cached);
            }
        }

        info!("Proving {} segments", num_segments);

        let result = (|| -> Result<ProveSegmentsResponse> {
            let (proofs, instance) = recover_and_prove(
                instance,
                &task.segments,
                &cached.sdk,
                &cached.exe,
                &cached.stdin,
            )?;

            info!(
                "{} segments proved in {:?}",
                num_segments,
                total_start.elapsed()
            );

            let upv_bytes = if task.compute_user_public_values {
                let upv = extract_user_public_values(&instance)?;
                Some(bitcode::serialize(&upv).wrap_err("serialize user public values")?)
            } else {
                None
            };

            let (final_proofs, is_leaf_proofs) = if task.aggregate_to_leaf && proofs.len() > 1 {
                let leaf_start = Instant::now();
                let leaf_proofs = aggregate_to_leaf(&cached.sdk, &proofs, task.num_children_leaf)?;
                info!(
                    "Leaf agg: {} → {} in {:?}",
                    proofs.len(),
                    leaf_proofs.len(),
                    leaf_start.elapsed()
                );
                (leaf_proofs, true)
            } else {
                (proofs, false)
            };

            let proof_bytes = final_proofs
                .into_iter()
                .map(|p| {
                    p.encode_to_vec()
                        .map_err(|e| eyre::eyre!("encode proof: {}", e))
                })
                .collect::<Result<Vec<_>>>()?;

            Ok(ProveSegmentsResponse {
                proof_bytes,
                user_public_values_bytes: upv_bytes,
                proving_time_ms: total_start.elapsed().as_millis() as u64,
                is_leaf_proofs,
            })
        })();

        (result, cached)
    }
}

fn aggregate_to_leaf(
    sdk: &Sdk,
    segment_proofs: &[Proof<SC>],
    num_children_leaf: usize,
) -> Result<Vec<Proof<SC>>> {
    use openvm_continuations::prover::ChildVkKind;

    let agg_prover = sdk.agg_prover();
    let leaf_prover = &agg_prover.leaf_prover;

    segment_proofs
        .chunks(num_children_leaf)
        .enumerate()
        .map(|(i, chunk)| {
            let _span = info_span!("worker_leaf_agg", idx = i).entered();
            Ok(leaf_prover.agg_prove_no_def::<DefaultStarkEngine>(chunk, ChildVkKind::App)?)
        })
        .collect()
}

#[cfg(feature = "cuda")]
pub fn run_grind_kernel(req: &crate::types::GrindRequest) -> Result<Option<u32>> {
    use openvm_cuda_backend::bn254_sponge::DeviceBn254SpongeState;
    use openvm_cuda_common::{
        common::get_device, copy::MemCopyH2D, d_buffer::DeviceBuffer, stream::GpuDeviceCtx,
    };

    let expected_size = std::mem::size_of::<DeviceBn254SpongeState>();
    if req.sponge_state_bytes.len() != expected_size {
        eyre::bail!(
            "sponge state size mismatch: got {} bytes, expected {}",
            req.sponge_state_bytes.len(),
            expected_size
        );
    }

    let sponge_state: DeviceBn254SpongeState = unsafe {
        std::ptr::read_unaligned(req.sponge_state_bytes.as_ptr() as *const DeviceBn254SpongeState)
    };

    let device_id =
        get_device().map_err(|e| eyre::eyre!("no GPU device available for grinding: {:?}", e))?;
    let ctx =
        GpuDeviceCtx::for_device(device_id as u32).wrap_err("create GPU context for grinding")?;

    let mut d_state: DeviceBuffer<DeviceBn254SpongeState> = DeviceBuffer::with_capacity_on(1, &ctx);
    [sponge_state].copy_to_on(&mut d_state, &ctx)?;

    let witness = unsafe {
        openvm_cuda_backend::cuda::bn254_merkle_tree::bn254_sponge_grind_range(
            d_state.as_ptr(),
            req.bits,
            req.min_witness,
            req.max_witness,
            req.witness_step,
            &ctx,
        )
    };

    match witness {
        Ok(w) => Ok(Some(w)),
        Err(openvm_cuda_backend::sponge::GrindError::WitnessNotFound) => Ok(None),
        Err(e) => Err(eyre::eyre!("grind kernel error: {:?}", e)),
    }
}
