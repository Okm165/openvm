# OpenVM Distributed Proving

Orchestrator-worker architecture for distributed GPU proving of OpenVM circuits.

## Design Principles

- **Stateless workers**: Each request carries all context. Workers build state, prove, clean up, return results.
- **Orchestrator delegates everything**: Segment proving, root proving, and Halo2 are all worker RPCs.
- **Symmetric workers**: All workers run the same binary. Any worker can handle any task.
- **GPU cleanup by default**: `release_and_reinit_pool()` runs after every operation — no process restarts needed.

## Worker API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Status, version, GPU info |
| `/prove` | POST | Self-contained segment proving (PK + ELF + stdin + segments) |
| `/prove/root` | POST | Root proving (stateless, circuit-independent) |
| `/prove/halo2` | POST | Halo2 proving (reads PK from local disk) |
| `/halo2/preload` | POST | Verify Halo2 PK exists on disk |
| `/grind` | POST | GPU grinding kernel |
| `/release-gpu` | POST | Force GPU memory release |

## Quick Start

```bash
# Build
cargo build --release --features halo2-gpu -p openvm-distributed

# Start workers (one per GPU node)
./openvm-worker --bind 0.0.0.0 --port 8002

# Run a proof
./openvm-orchestrator \
  --workers http://node0:8002,http://node1:8002 \
  --elf program.elf --config openvm.toml \
  --evm --halo2-pk-cache ~/.openvm/halo2.pk \
  --kzg-params-dir ~/.openvm/params
```

## Pipeline Flow

```
Orchestrator                    Workers
    │
    ├─ E2 metered execution ──→ (CPU only)
    ├─ Assign segments
    ├─ POST /prove ───────────→ Worker 0: prove segments [0..N/2]
    ├─ POST /prove ───────────→ Worker 1: prove segments [N/2..N]
    │                           ↓ release_and_reinit_pool()
    ├─ Aggregation (CPU)
    ├─ STARK verify
    ├─ release_and_reinit_pool()
    ├─ POST /prove/root ──────→ Worker (round-robin)
    │                           ↓ release_and_reinit_pool()
    └─ POST /prove/halo2 ─────→ Worker (round-robin, retry on fail)
                                ↓ release_and_reinit_pool()
```
