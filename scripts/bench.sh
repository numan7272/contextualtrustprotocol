#!/usr/bin/env bash
# CTP end-to-end benchmark: start the guard and orchestrator, wait until both
# are listening, push the payload corpora through the gateway, write the
# results, and clean up the processes. Run ./scripts/setup.sh first.
# Runs on any Linux with bash (the TCP readiness check uses bash's /dev/tcp).
#
# Override via the environment, for example:
#   CONFIG=ctp.local.toml HOST=127.0.0.1 PORT=50051 ./scripts/bench.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CONFIG="${CONFIG:-$REPO_ROOT/ctp.local.toml}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-50051}"
ADDR="${ADDR:-http://$HOST:$PORT}"
SOCKET_PATH="${SOCKET_PATH:-/tmp/ctp/guard.sock}"
BENIGN="${BENIGN:-$REPO_ROOT/payloads/benign.txt}"
INJECTIONS="${INJECTIONS:-$REPO_ROOT/payloads/injections.txt}"
CSV_OUT="${CSV_OUT:-$REPO_ROOT/bench-results.csv}"
MD_OUT="${MD_OUT:-$REPO_ROOT/bench-results.md}"

GUARD_BIN="$REPO_ROOT/target/release/ctp-guard"
ORCH_BIN="$REPO_ROOT/target/release/ctp-orchestrator"
BENCH_BIN="$REPO_ROOT/target/release/examples/bench_client"

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

for bin in "$GUARD_BIN" "$ORCH_BIN" "$BENCH_BIN"; do
  [ -x "$bin" ] || die "Missing $bin. Run ./scripts/setup.sh first."
done
[ -f "$CONFIG" ] || die "Missing config $CONFIG. Run ./scripts/setup.sh first."

GUARD_PID=""
ORCH_PID=""
cleanup() {
  info "Cleaning up"
  [ -n "$ORCH_PID" ]  && kill "$ORCH_PID"  2>/dev/null || true
  [ -n "$GUARD_PID" ] && kill "$GUARD_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -f "$SOCKET_PATH" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

wait_for() { # description, test-command, attempts
  local desc="$1" attempts="${3:-60}"
  for _ in $(seq 1 "$attempts"); do
    if eval "$2" 2>/dev/null; then return 0; fi
    sleep 0.5
  done
  return 1
}

# --- guard ------------------------------------------------------------------
rm -f "$SOCKET_PATH" 2>/dev/null || true
info "Starting guard ($GUARD_BIN)"
RUST_LOG="${RUST_LOG:-warn}" "$GUARD_BIN" "$CONFIG" > "$REPO_ROOT/guard.log" 2>&1 &
GUARD_PID=$!
wait_for "guard socket" "[ -S '$SOCKET_PATH' ]" 120 \
  || die "Guard did not create its socket. See guard.log (model load can take a while)."
kill -0 "$GUARD_PID" 2>/dev/null || die "Guard exited early. See guard.log."

# --- orchestrator -----------------------------------------------------------
info "Starting orchestrator ($ORCH_BIN)"
RUST_LOG="${RUST_LOG:-warn}" "$ORCH_BIN" "$CONFIG" > "$REPO_ROOT/orch.log" 2>&1 &
ORCH_PID=$!
wait_for "orchestrator port" "timeout 1 bash -c '</dev/tcp/$HOST/$PORT'" 60 \
  || die "Orchestrator did not start listening on $HOST:$PORT. See orch.log."

# --- run --------------------------------------------------------------------
info "Sending payloads through $ADDR"
"$BENCH_BIN" "$ADDR" "$BENIGN" "$INJECTIONS" "$CSV_OUT" | tee "$MD_OUT"

echo
info "Results: $MD_OUT (markdown), $CSV_OUT (csv)"
