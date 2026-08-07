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

use crate::types::{ProveRequest, ProveSegmentsResponse, SegmentDescriptor};

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

/// Self-contained proving: deserialize context, build state, prove, drop everything.
/// This is the primary entry point — the worker receives all context in one request.
#[instrument(name = "worker_prove", skip_all, fields(num_segments = req.segments.len()))]
pub(crate) fn prove_from_request(req: ProveRequest) -> Result<ProveSegmentsResponse> {
    let total_start = Instant::now();
    let num_segments = req.segments.len();

    if num_segments == 0 {
        return Err(eyre::eyre!("received empty segment list"));
    }

    for window in req.segments.windows(2) {
        if window[0].instret_start + window[0].num_insns != window[1].instret_start {
            return Err(eyre::eyre!(
                "Segment descriptors not contiguous: {} + {} != {}",
                window[0].instret_start,
                window[0].num_insns,
                window[1].instret_start
            ));
        }
    }

    info!(
        "Proving {} segments (pk={} B, exe={} B, stdin={} B)",
        num_segments,
        req.app_pk_bytes.len(),
        req.exe_bytes.len(),
        req.stdin_bytes.len(),
    );

    let app_pk: AppProvingKey<SdkVmConfig> =
        bitcode::deserialize(&req.app_pk_bytes).wrap_err("deserialize app_pk")?;
    let exe: VmExe<F> = bitcode::deserialize(&req.exe_bytes).wrap_err("deserialize exe")?;
    let stdin: StdIn<F> = bitcode::deserialize(&req.stdin_bytes).wrap_err("deserialize stdin")?;

    let sdk = Sdk::builder()
        .app_pk(app_pk)
        .agg_params(AggregationSystemParams::default())
        .build()
        .wrap_err("build SDK")?;

    let exe = Arc::new(exe);
    let app_pk = sdk.app_pk();
    let instance = new_local_prover(*sdk.app_vm_builder(), &app_pk.app_vm_pk, exe.clone())
        .wrap_err("create VmInstance")?;

    info!("Setup done in {:.2}s", total_start.elapsed().as_secs_f64());

    let (proofs, instance) = recover_and_prove(instance, &req.segments, &sdk, &exe, &stdin)?;

    info!(
        "{} segments proved in {:?}",
        num_segments,
        total_start.elapsed()
    );

    let upv_bytes = if req.compute_user_public_values {
        let upv = extract_user_public_values(&instance)?;
        Some(bitcode::serialize(&upv).wrap_err("serialize user public values")?)
    } else {
        None
    };

    let (final_proofs, is_leaf_proofs) = if req.aggregate_to_leaf && proofs.len() > 1 {
        let leaf_start = Instant::now();
        let leaf_proofs = aggregate_to_leaf(&sdk, &proofs, req.num_children_leaf)?;
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

    drop(instance);
    drop(sdk);

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
            leaf_prover.agg_prove_no_def::<DefaultStarkEngine>(chunk, ChildVkKind::App)
        })
        .collect()
}

#[cfg(feature = "cuda")]
pub(crate) fn run_grind_kernel(req: &crate::types::GrindRequest) -> Result<Option<u32>> {
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

// ─── Root proving delegation (standalone — no WorkerState needed) ─────────────

#[cfg(feature = "cuda")]
fn decode_metadata(bytes: &[u8]) -> Result<openvm_sdk::prover::InternalLayerMetadata> {
    if bytes.len() < 9 {
        return Err(eyre::eyre!("metadata too short: {} bytes", bytes.len()));
    }
    let internal_recursive_layer = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let internal_node_idx = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let proofs_type = match bytes[8] {
        0 => openvm_continuations::circuit::inner::ProofsType::Vm,
        1 => openvm_continuations::circuit::inner::ProofsType::Deferral,
        2 => openvm_continuations::circuit::inner::ProofsType::Mix,
        3 => openvm_continuations::circuit::inner::ProofsType::Combined,
        _ => return Err(eyre::eyre!("invalid proofs_type byte: {}", bytes[8])),
    };
    Ok(openvm_sdk::prover::InternalLayerMetadata {
        internal_recursive_layer,
        internal_node_idx,
        proofs_type,
    })
}

#[cfg(feature = "cuda")]
fn do_root_prove(
    task: &crate::types::RootProveTask,
    sdk: &Sdk,
) -> Result<crate::types::RootProveResponse> {
    use openvm_stark_backend::codec::Decode;
    use openvm_verify_stark_host::VmStarkProof;

    let start = Instant::now();

    info!(
        "Deserializing VmStarkProof ({} bytes)...",
        task.proof_bytes.len()
    );
    let proof: VmStarkProof = VmStarkProof::decode_from_bytes(&task.proof_bytes)
        .map_err(|e| eyre::eyre!("decode VmStarkProof: {}", e))?;

    let mut metadata = decode_metadata(&task.metadata_bytes)?;

    let root_prover = sdk.root_prover();
    let agg_prover = sdk.agg_prover();
    #[allow(unused_mut)]
    let mut root_engine = root_prover.create_engine();

    #[cfg(feature = "cuda")]
    root_engine.device_mut().set_cache_rs_code_matrix(true);

    info!("Starting root proving...");
    let root_proof = root_prover
        .prove(proof, &root_engine, 8, |p| {
            agg_prover.wrap_proof(p, &mut metadata)
        })
        .wrap_err("root proving failed")?;

    let proving_ms = start.elapsed().as_millis() as u64;
    let root_proof_bytes = root_proof.encode_to_vec().wrap_err("encode root proof")?;
    info!("Root proof encoded: {} bytes", root_proof_bytes.len());

    Ok(crate::types::RootProveResponse {
        root_proof_bytes,
        proving_time_ms: proving_ms,
    })
}

/// Build SDK from scratch and run root proving (stateless path).
///
/// Root + aggregation provers are circuit-independent — they depend only on
/// AggregationSystemParams, not the specific app config. We provide a
/// minimal riscv32 config to satisfy the SDK builder requirement.
#[cfg(feature = "cuda")]
pub(crate) fn prove_root_standalone(
    task: &crate::types::RootProveTask,
) -> Result<crate::types::RootProveResponse> {
    use openvm_sdk::config::{AggregationSystemParams, AppConfig};
    use openvm_stark_sdk::config::{app_params_with_100_bits_security, MAX_APP_LOG_STACKED_HEIGHT};

    let app_params = app_params_with_100_bits_security(MAX_APP_LOG_STACKED_HEIGHT);
    let app_config = AppConfig::new(SdkVmConfig::riscv32(), app_params);

    let sdk = Sdk::builder()
        .app_config(app_config)
        .agg_params(AggregationSystemParams::default())
        .build()
        .wrap_err("build SDK for root proving")?;

    do_root_prove(task, &sdk)
}

// ─── Halo2 proving (in-process) ──────────────────────────────────────────────
//
// Halo2 needs ~21 GiB VRAM. Before this function is called, the server handler
// drops all STARK state and calls release_and_reinit_pool() — which frees all
// VPMM pages, small allocations, and VA reservations — returning physical GPU
// memory to the driver for Halo2's own hipMalloc allocations.

#[cfg(feature = "evm")]
pub(crate) fn prove_halo2_inline(
    task: &crate::types::Halo2ProveTask,
) -> Result<crate::types::Halo2ProveResponse> {
    use std::path::Path;

    use openvm_stark_backend::codec::Decode;

    let halo2_pk_path = Path::new(&task.halo2_pk_path);
    if !halo2_pk_path.exists() {
        return Err(eyre::eyre!(
            "Halo2 PK not found at {:?} on this worker",
            halo2_pk_path
        ));
    }

    let halo2_start = Instant::now();

    info!(
        "Decoding root proof ({:.1} MB)...",
        task.root_proof_bytes.len() as f64 / 1_048_576.0
    );
    let root_proof: openvm_stark_backend::proof::Proof<openvm_continuations::RootSC> =
        openvm_stark_backend::proof::Proof::decode_from_bytes(&task.root_proof_bytes)
            .map_err(|e| eyre::eyre!("decode root proof: {}", e))?;

    info!("Loading Halo2 PK from {:?}...", halo2_pk_path);
    let pk_data = std::fs::read(halo2_pk_path).map_err(|e| eyre::eyre!("read Halo2 PK: {}", e))?;
    info!("PK loaded ({:.1} GB)", pk_data.len() as f64 / 1e9);

    let pk: openvm_sdk::keygen::Halo2ProvingKey = {
        let mut cursor = std::io::Cursor::new(&pk_data);
        openvm_sdk::keygen::Halo2ProvingKey::decode(&mut cursor)
            .map_err(|e| eyre::eyre!("decode Halo2 PK: {}", e))?
    };
    drop(pk_data);

    let params_reader = match task.kzg_params_dir.as_deref() {
        Some(dir) => openvm_sdk::halo2_params::CacheHalo2ParamsReader::new(dir),
        None => openvm_sdk::halo2_params::CacheHalo2ParamsReader::new_with_default_params_dir(),
    };

    info!("Generating Halo2 verifier...");
    let verifier = openvm_sdk::solidity::generate_halo2_verifier_solidity(&pk, &params_reader)?;

    let prover = openvm_sdk::prover::Halo2Prover::new(&params_reader, pk);

    info!("Halo2 proof generation...");
    let prove_start = Instant::now();
    let evm_proof = prover.prove_for_evm(&root_proof)?;
    info!("Halo2 proof generated in {:?}", prove_start.elapsed());

    info!("EVM verification...");
    let verify_start = Instant::now();
    let gas_cost = openvm_sdk::Sdk::verify_evm_halo2_proof(&verifier, evm_proof, None)?;
    info!(
        "EVM verify: {:?}, gas: {}",
        verify_start.elapsed(),
        gas_cost
    );

    let proving_ms = halo2_start.elapsed().as_millis() as u64;
    info!("Halo2 total: {}ms, gas: {}", proving_ms, gas_cost);

    Ok(crate::types::Halo2ProveResponse {
        gas_cost,
        proving_time_ms: proving_ms,
    })
}

#[cfg(not(feature = "evm"))]
pub(crate) fn prove_halo2_inline(
    _task: &crate::types::Halo2ProveTask,
) -> Result<crate::types::Halo2ProveResponse> {
    Err(eyre::eyre!(
        "Halo2 proving requires the `evm` feature. Rebuild with --features halo2-gpu"
    ))
}
