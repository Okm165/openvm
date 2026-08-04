use std::{sync::Arc, time::Instant};

use eyre::{bail, Context, Result};
use openvm_circuit::{
    arch::{execution_mode::Segment, instructions::exe::VmExe, ContinuationVmProof},
    system::{
        memory::{merkle::public_values::UserPublicValuesProof, CHUNK},
        program::trace::compute_exe_commit_from_mem_config,
    },
};
use openvm_continuations::prover::ChildVkKind;
use openvm_sdk::{
    prover::{vm::new_local_prover, InternalLayerMetadata},
    DefaultStarkEngine, Sdk, StdIn, F, SC,
};
use openvm_sdk_config::SdkVmBuilder;
use openvm_stark_backend::{codec::Decode, proof::Proof};
use openvm_verify_stark_host::{vk::VerificationBaseline, VmStarkProof};
use tracing::{info, info_span, instrument};

use crate::{
    assignment::assign_segments,
    client::WorkerClient,
    types::{SegmentDescriptor, SegmentTask},
};

pub struct DistributedProveResult {
    pub proof: VmStarkProof,
    pub metadata: openvm_sdk::prover::InternalLayerMetadata,
    pub baseline: VerificationBaseline,
}

pub struct DistributedProver {
    sdk: Sdk,
    exe: Arc<VmExe<F>>,
    stdin: StdIn<F>,
    workers: Vec<WorkerClient>,
    leaf_aggregate: bool,
}

impl DistributedProver {
    pub fn new(sdk: Sdk, exe: Arc<VmExe<F>>, stdin: StdIn<F>, workers: Vec<WorkerClient>) -> Self {
        Self {
            sdk,
            exe,
            stdin,
            workers,
            leaf_aggregate: true,
        }
    }

    pub fn set_leaf_aggregate(&mut self, enabled: bool) {
        self.leaf_aggregate = enabled;
    }

    pub fn sdk(&self) -> &Sdk {
        &self.sdk
    }

    pub fn into_sdk(self) -> Sdk {
        self.sdk
    }

    pub fn remote_workers(&self) -> Vec<WorkerClient> {
        self.workers
            .iter()
            .filter(|w| !w.is_local())
            .cloned()
            .collect()
    }

    pub async fn shutdown_local_workers(&self) {
        for worker in self.workers.iter().filter(|w| w.is_local()) {
            info!("Shutting down local worker {}", worker.base_url());
            if let Err(e) = worker.shutdown().await {
                tracing::warn!("Worker {} shutdown failed: {}", worker.base_url(), e);
            }
        }
    }

    #[instrument(name = "distributed_prove", skip_all)]
    pub async fn prove(&self) -> Result<DistributedProveResult> {
        let total_start = Instant::now();

        if self.workers.is_empty() {
            bail!("No workers configured. Add at least one --workers URL.");
        }

        let payload_bytes = Arc::new(self.build_setup_payload_bytes()?);

        info!("Phase 1: Metered execution (E2)");
        let e2_start = Instant::now();
        let (segments, baseline) = self.run_metered_execution()?;
        let num_segments = segments.len();
        let e2_duration = e2_start.elapsed();
        info!("E2: {} segments in {:?}", num_segments, e2_duration);

        if num_segments == 0 {
            bail!("Program produced no segments (immediate termination?)");
        }
        if num_segments > 1 {
            let total_insns: u64 = segments.iter().map(|s| s.num_insns).sum();
            info!(
                "Segment stats: {} total insns across {} segments",
                total_insns, num_segments
            );
        }

        let setup_start = Instant::now();
        let mut setup_futures = Vec::with_capacity(self.workers.len());
        for worker in &self.workers {
            let w = worker.clone();
            let bytes = Arc::clone(&payload_bytes);
            setup_futures.push(tokio::spawn(
                async move { w.setup_with_bytes(&bytes).await },
            ));
        }
        for future in setup_futures {
            future
                .await
                .map_err(|e| eyre::eyre!("setup task panicked: {}", e))??;
        }
        let setup_duration = setup_start.elapsed();
        info!("Setup: {:?}", setup_duration);

        info!(
            "Phase 2: Proving {} segments across {} workers",
            num_segments,
            self.workers.len()
        );
        let prove_start = Instant::now();
        let (segment_proofs, user_public_values, got_leaf_proofs) =
            self.prove_segments(&segments).await?;
        let prove_duration = prove_start.elapsed();
        info!("Proving: {:?}", prove_duration);

        let heavy_aggregation = segment_proofs.len() > 1;
        if heavy_aggregation {
            self.shutdown_local_workers().await;
        }
        for worker in self.workers.iter().filter(|w| !w.is_local()) {
            if let Err(e) = worker.release_gpu().await {
                tracing::warn!("Worker {} GPU release failed: {}", worker.base_url(), e);
            }
        }
        crate::release_cuda_memory();
        if heavy_aggregation {
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        }
        info!(
            "Phase 3: Aggregation ({} proofs, leaf={})",
            segment_proofs.len(),
            got_leaf_proofs
        );
        let agg_start = Instant::now();
        let result = if got_leaf_proofs {
            self.aggregate_from_leaf_proofs(segment_proofs, user_public_values)?
        } else {
            let continuation_proof = ContinuationVmProof {
                per_segment: segment_proofs,
                user_public_values,
            };
            let agg_prover = self.sdk.agg_prover();
            agg_prover.prove_vm(continuation_proof)?
        };
        let agg_duration = agg_start.elapsed();
        let total_duration = total_start.elapsed();
        info!(
            "=== Timing: E2={:.1}s setup={:.1}s prove={:.1}s agg={:.1}s total={:.1}s ===",
            e2_duration.as_secs_f64(),
            setup_duration.as_secs_f64(),
            prove_duration.as_secs_f64(),
            agg_duration.as_secs_f64(),
            total_duration.as_secs_f64(),
        );

        Ok(DistributedProveResult {
            proof: result.0,
            metadata: result.1,
            baseline,
        })
    }

    fn run_metered_execution(&self) -> Result<(Vec<Segment>, VerificationBaseline)> {
        use openvm_circuit::arch::VmInstance;
        let _span = info_span!("e2_metered_execution").entered();
        let app_pk = self.sdk.app_pk();
        let instance: VmInstance<DefaultStarkEngine, SdkVmBuilder> = new_local_prover(
            *self.sdk.app_vm_builder(),
            &app_pk.app_vm_pk,
            self.exe.clone(),
        )
        .wrap_err("create VmInstance for E2")?;

        let exe = instance.exe().clone();
        let metered_ctx = instance.vm.build_metered_ctx(&exe);
        let metered_interpreter = instance.vm.metered_interpreter(&exe)?;
        let (segments, _) = metered_interpreter.execute_metered(self.stdin.clone(), metered_ctx)?;

        let baseline = self.build_verification_baseline(&instance);
        drop(instance);
        crate::release_cuda_memory();

        Ok((segments, baseline))
    }

    fn build_verification_baseline(
        &self,
        instance: &openvm_circuit::arch::VmInstance<DefaultStarkEngine, SdkVmBuilder>,
    ) -> VerificationBaseline {
        let app_exe_commit = compute_exe_commit_from_mem_config(
            instance.program_commitment(),
            instance.exe(),
            &instance.vm.config().as_ref().memory_config,
        );
        let memory_dimensions = instance
            .vm
            .config()
            .as_ref()
            .memory_config
            .memory_dimensions();
        let num_user_pvs = instance.vm.config().as_ref().num_public_values;
        let agg_prover = self.sdk.agg_prover();

        VerificationBaseline {
            app_exe_commit,
            memory_dimensions,
            num_user_pvs,
            app_vk_commit: agg_prover.leaf_prover.get_vk_commit(false),
            leaf_vk_commit: agg_prover.internal_for_leaf_prover.get_vk_commit(false),
            internal_for_leaf_vk_commit: agg_prover.internal_recursive_prover.get_vk_commit(false),
            internal_recursive_vk_commit: agg_prover.internal_recursive_prover.get_vk_commit(true),
            expected_def_hook_commit: openvm_sdk::DeferralSetup::default().hook_commit(),
        }
    }

    fn build_setup_payload_bytes(&self) -> Result<Vec<u8>> {
        let app_pk = self.sdk.app_pk();
        let payload = crate::types::SetupPayload {
            app_pk_bytes: bitcode::serialize(app_pk).wrap_err("serialize app_pk")?,
            exe_bytes: bitcode::serialize(&*self.exe).wrap_err("serialize exe")?,
            stdin_bytes: bitcode::serialize(&self.stdin).wrap_err("serialize stdin")?,
        };
        info!(
            "Payload: pk={} exe={} stdin={} bytes",
            payload.app_pk_bytes.len(),
            payload.exe_bytes.len(),
            payload.stdin_bytes.len()
        );
        bitcode::serialize(&payload).wrap_err("serialize setup payload")
    }

    fn aggregate_from_leaf_proofs(
        &self,
        leaf_proofs: Vec<Proof<SC>>,
        user_public_values: UserPublicValuesProof<CHUNK, F>,
    ) -> Result<(VmStarkProof, InternalLayerMetadata)> {
        use openvm_continuations::circuit::inner::ProofsType;

        let agg_prover = self.sdk.agg_prover();
        let chunk_size = self.sdk.agg_tree_config().num_children_internal;

        info!(
            "Internal aggregation from {} leaf proofs (chunk_size={})",
            leaf_proofs.len(),
            chunk_size
        );

        let mut node_idx: i32 = -1;

        macro_rules! agg_layer {
            ($proofs:expr, $prover:expr, $kind:expr, $label:expr) => {
                info_span!("agg_layer", group = $label).in_scope(|| {
                    $proofs
                        .chunks(chunk_size)
                        .map(|chunk| {
                            node_idx += 1;
                            info_span!("agg_node", idx = node_idx).in_scope(|| {
                                $prover.agg_prove_no_def::<DefaultStarkEngine>(chunk, $kind)
                            })
                        })
                        .collect::<eyre::Result<Vec<_>>>()
                })?
            };
        }

        let mut proofs = agg_layer!(
            leaf_proofs,
            agg_prover.internal_for_leaf_prover,
            ChildVkKind::Standard,
            "internal_for_leaf"
        );

        proofs = agg_layer!(
            proofs,
            agg_prover.internal_recursive_prover,
            ChildVkKind::Standard,
            "internal_recursive.0"
        );

        let mut layer = 1u32;
        while proofs.len() > 1 {
            let label = format!("internal_recursive.{layer}");
            proofs = agg_layer!(
                proofs,
                agg_prover.internal_recursive_prover,
                ChildVkKind::RecursiveSelf,
                &label
            );
            layer += 1;
        }

        Ok((
            VmStarkProof {
                inner: proofs.pop().unwrap(),
                user_pvs_proof: user_public_values,
                deferral_merkle_proofs: None,
            },
            InternalLayerMetadata {
                internal_recursive_layer: layer,
                internal_node_idx: node_idx as u32,
                proofs_type: ProofsType::Vm,
            },
        ))
    }

    async fn prove_segments(
        &self,
        segments: &[Segment],
    ) -> Result<(Vec<Proof<SC>>, UserPublicValuesProof<CHUNK, F>, bool)> {
        let num_segments = segments.len();
        let num_workers = self.workers.len();

        let assignments = assign_segments(segments, num_workers);
        if assignments.len() > num_workers {
            bail!(
                "BUG: more assignments ({}) than workers ({})",
                assignments.len(),
                num_workers
            );
        }
        crate::assignment::validate_assignments(&assignments, num_segments)?;

        info!("Segment assignments: {:?}", assignments);

        let num_children_leaf = self.sdk.agg_tree_config().num_children_leaf;
        let aggregate_to_leaf = self.leaf_aggregate
            && num_segments > 1
            && assignments.iter().all(|a| a.end - a.start > 1);

        if self.leaf_aggregate && !aggregate_to_leaf && num_segments > 1 {
            info!("Leaf aggregation disabled: some workers have only 1 segment");
        }

        let mut all_proofs: Vec<Option<Vec<Proof<SC>>>> = vec![None; assignments.len()];
        let mut futures = Vec::with_capacity(assignments.len());

        for (assign_idx, assignment) in assignments.iter().enumerate() {
            let segment_descs: Vec<SegmentDescriptor> = segments[assignment.start..assignment.end]
                .iter()
                .map(SegmentDescriptor::from)
                .collect();

            let is_last_assignment = assign_idx == assignments.len() - 1;
            let task = SegmentTask {
                segments: segment_descs,
                compute_user_public_values: is_last_assignment,
                aggregate_to_leaf,
                num_children_leaf,
            };

            let client = self.workers[assign_idx].clone();

            info!(
                "→ {} segs [{}-{}] ({} insns) to {}",
                task.segments.len(),
                assignment.start,
                assignment.end - 1,
                assignment.total_insns,
                client.base_url(),
            );

            futures.push(tokio::spawn(async move {
                let start = Instant::now();
                let result = client.prove_segments(&task).await;
                let elapsed = start.elapsed();
                (assign_idx, result, elapsed)
            }));
        }

        let mut user_public_values = None;
        let mut got_leaf_proofs = false;

        for future in futures {
            let (assign_idx, result, elapsed) = future.await.wrap_err("worker task panicked")?;
            let response = result?;

            if response.is_leaf_proofs {
                got_leaf_proofs = true;
            }

            info!(
                "← {} proofs in {:?} ({:.1}s self-reported)",
                response.proof_bytes.len(),
                elapsed,
                response.proving_time_ms as f64 / 1000.0,
            );

            if !response.is_leaf_proofs {
                let expected_count = assignments[assign_idx].end - assignments[assign_idx].start;
                if response.proof_bytes.len() != expected_count {
                    bail!(
                        "Worker returned {} proofs but expected {} for assignment [{}, {})",
                        response.proof_bytes.len(),
                        expected_count,
                        assignments[assign_idx].start,
                        assignments[assign_idx].end,
                    );
                }
            } else {
                let num_segs = assignments[assign_idx].end - assignments[assign_idx].start;
                let expected_leafs = num_segs.div_ceil(num_children_leaf);
                if response.proof_bytes.len() != expected_leafs {
                    bail!(
                        "Worker returned {} leaf proofs but expected {} (from {} segments, chunk_size={})",
                        response.proof_bytes.len(), expected_leafs, num_segs, num_children_leaf,
                    );
                }
            }

            let proofs: Vec<Proof<SC>> = response
                .proof_bytes
                .into_iter()
                .map(|bytes| Proof::decode_from_bytes(&bytes))
                .collect::<std::io::Result<Vec<_>>>()
                .wrap_err("failed to decode worker proofs")?;

            all_proofs[assign_idx] = Some(proofs);

            if let Some(upv_bytes) = response.user_public_values_bytes {
                if assign_idx != assignments.len() - 1 {
                    bail!(
                        "BUG: received UPV from non-final worker (assignment {})",
                        assign_idx
                    );
                }
                let upv: UserPublicValuesProof<CHUNK, F> =
                    bitcode::deserialize(&upv_bytes).wrap_err("deserialize user public values")?;
                user_public_values = Some(upv);
            }
        }

        let final_proofs: Vec<_> = all_proofs.into_iter().flatten().flatten().collect();

        if final_proofs.is_empty() {
            bail!("No proofs received from any worker");
        }
        if !got_leaf_proofs && final_proofs.len() != num_segments {
            bail!(
                "expected {} segment proofs, got {}",
                num_segments,
                final_proofs.len()
            );
        }

        let upv = user_public_values.ok_or_else(|| {
            eyre::eyre!("UPV not computed: last worker must set compute_user_public_values=true")
        })?;

        Ok((final_proofs, upv, got_leaf_proofs))
    }
}
