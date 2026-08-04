#!/usr/bin/env bash
set -euo pipefail

# Run all benchmark circuits through the distributed EVM pipeline sequentially.
# Both workers must be running before invoking this script.
#
# Usage: ./bench_all_evm.sh [--workers URL,URL] [--output-dir DIR]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="${REPO_ROOT}/target/release"
GUEST="${REPO_ROOT}/benchmarks/guest"
DATA="${SCRIPT_DIR}/bench-data"

WORKERS="${WORKERS:-http://localhost:8002,http://10.4.4.101:8002}"
OUT="${OUTPUT_DIR:-/tmp/openvm-bench}"
HALO2_PK="${HALO2_PK_CACHE:-${HOME}/.openvm/halo2.pk}"
KZG_DIR="${KZG_PARAMS_DIR:-${HOME}/.openvm/params}"

while [[ $# -gt 0 ]]; do
    case $1 in
        --workers) WORKERS="$2"; shift 2 ;;
        --output-dir) OUT="$2"; shift 2 ;;
        --halo2-pk) HALO2_PK="$2"; shift 2 ;;
        --kzg-dir) KZG_DIR="$2"; shift 2 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

mkdir -p "$OUT"
ORCH="${BIN}/openvm-orchestrator"
[[ -x "$ORCH" ]] || { echo "Missing: $ORCH"; exit 1; }
[[ -f "$HALO2_PK" ]] || { echo "Missing halo2 PK: $HALO2_PK (run --keygen-halo2 first)"; exit 1; }

# Circuit definitions: name|elf|config|stdin_file (empty = no stdin)
# --stdin auto-detects format: bitcode StdIn<F> (.stdin) or raw bytes (.txt/.bin)
CIRCUITS=(
    "fibonacci|fibonacci/elf/openvm-fibonacci-program.elf|fibonacci/openvm.toml|${DATA}/fibonacci.stdin"
    "keccak|keccak256_iter/elf/openvm-keccak256-iter-program.elf|keccak256_iter/openvm.toml|${DATA}/keccak.stdin"
    "sha2_bench|sha2_bench/elf/openvm-sha2-bench-program.elf|sha2_bench/openvm.toml|${DATA}/sha2_bench.stdin"
    "ecrecover|ecrecover/elf/openvm-ecdsa-recover-key-program.elf|ecrecover/openvm.toml|${DATA}/ecrecover.stdin"
    "pairing|pairing/elf/openvm-pairing-program.elf|pairing/openvm.toml|"
    "kitchen_sink|kitchen-sink/elf/openvm-kitchen-sink-program.elf|kitchen-sink/openvm.toml|"
    "regex|regex/elf/openvm-regex-program.elf|regex/openvm.toml|${GUEST}/regex/regex_email.txt"
    "revm_transfer|revm_transfer/elf/openvm-revm-transfer.elf|revm_transfer/openvm.toml|"
    "merkle_tree|merkle_tree/elf/openvm-merkle-tree-program.elf|merkle_tree/openvm.toml|"
    "base64_json|base64_json/elf/openvm-json-program.elf|base64_json/openvm.toml|${GUEST}/base64_json/json_payload_encoded.txt"
    "bincode|bincode/elf/openvm-bincode-program.elf|bincode/openvm.toml|${GUEST}/bincode/minecraft_savedata.bin"
    "rkyv|rkyv/elf/openvm-rkyv-program.elf|rkyv/openvm.toml|${GUEST}/rkyv/minecraft_savedata.bin"
)

RESULTS="$OUT/bench_results.txt"
printf "# Distributed EVM Pipeline | %s | Workers: %s\n" "$(date -Iseconds)" "$WORKERS" > "$RESULTS"

echo "Running ${#CIRCUITS[@]} circuits (workers: $WORKERS)"
echo ""

PASS=0 FAIL=0
for entry in "${CIRCUITS[@]}"; do
    IFS='|' read -r NAME ELF CONFIG STDIN_FILE <<< "$entry"
    ELF_PATH="${GUEST}/${ELF}"
    CONFIG_PATH="${GUEST}/${CONFIG}"

    [[ -f "$ELF_PATH" ]] || { echo "SKIP $NAME (no ELF)"; echo "$NAME | SKIP | -" >> "$RESULTS"; ((FAIL++)) || true; continue; }

    CMD=("$ORCH" --workers "$WORKERS" --elf "$ELF_PATH" --config "$CONFIG_PATH"
        --evm --halo2-pk-cache "$HALO2_PK" --kzg-params-dir "$KZG_DIR" --halo2-subprocess)

    [[ -n "$STDIN_FILE" ]] && CMD+=(--stdin "$STDIN_FILE")

    echo "--- $NAME ---"
    START=$(date +%s%N)
    set +e
    "${CMD[@]}" 2>&1 | tee "$OUT/${NAME}.log"
    RC=${PIPESTATUS[0]}
    set -e
    ELAPSED=$(awk "BEGIN {printf \"%.1f\", ($(date +%s%N) - $START) / 1e9}")

    if [[ $RC -eq 0 ]]; then
        echo "  OK ${NAME} ${ELAPSED}s"
        echo "$NAME | ${ELAPSED}s | OK" >> "$RESULTS"
        ((PASS++)) || true
    else
        echo "  FAIL ${NAME} (rc=$RC) ${ELAPSED}s"
        echo "$NAME | ${ELAPSED}s | FAIL($RC)" >> "$RESULTS"
        ((FAIL++)) || true
    fi
    echo ""
done

echo "=== DONE: $PASS passed, $FAIL failed ==="
cat "$RESULTS"
