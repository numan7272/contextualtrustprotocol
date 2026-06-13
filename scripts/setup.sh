#!/usr/bin/env bash
# CTP setup: check dependencies, fetch a GGUF model, build the llama-backed
# guard plus the orchestrator and bench client, and write a local test config.
# One command to get from a fresh WSL2 to a runnable end-to-end benchmark.
#
# Override anything via the environment, for example:
#   GUARD_FEATURES=llama,vulkan ./scripts/setup.sh     # build with GPU (Vulkan)
#   MODEL_PATH=/data/guard.gguf  ./scripts/setup.sh     # use your own model
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

GUARD_FEATURES="${GUARD_FEATURES:-llama}"
MODEL_PATH="${MODEL_PATH:-$REPO_ROOT/models/qwen2.5-0.5b-instruct-q4_k_m.gguf}"
MODEL_URL="${MODEL_URL:-https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf}"
CONFIG_OUT="${CONFIG_OUT:-$REPO_ROOT/ctp.local.toml}"
SOCKET_PATH="${SOCKET_PATH:-/tmp/ctp/guard.sock}"

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# --- dependencies -----------------------------------------------------------
info "Checking dependencies"
missing=0

if ! command -v cargo >/dev/null 2>&1; then
  warn "Rust/cargo not found. Install: https://rustup.rs"
  missing=1
fi
if ! command -v cmake >/dev/null 2>&1; then
  warn "cmake not found. Install: sudo apt install cmake"
  missing=1
fi

# libclang is needed by bindgen when building llama-cpp-sys.
LIBCLANG_DIR=""
if command -v ldconfig >/dev/null 2>&1; then
  LIBCLANG_DIR="$(ldconfig -p 2>/dev/null | grep -m1 'libclang' | sed -E 's/.*=> (.*)\/[^/]+$/\1/' || true)"
fi
if [ -z "$LIBCLANG_DIR" ] && [ -n "${LIBCLANG_PATH:-}" ]; then
  LIBCLANG_DIR="$LIBCLANG_PATH"
fi
if [ -z "$LIBCLANG_DIR" ]; then
  warn "libclang not found. Install: sudo apt install libclang-dev"
  missing=1
else
  export LIBCLANG_PATH="$LIBCLANG_DIR"
  info "libclang: $LIBCLANG_PATH"
fi

[ "$missing" -eq 0 ] || die "Install the missing dependencies above and re-run."

# --- model ------------------------------------------------------------------
if [ -f "$MODEL_PATH" ] && [ -s "$MODEL_PATH" ]; then
  info "Model present: $MODEL_PATH"
else
  info "Downloading model -> $MODEL_PATH"
  mkdir -p "$(dirname "$MODEL_PATH")"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 -C - -o "$MODEL_PATH" "$MODEL_URL"
  elif command -v wget >/dev/null 2>&1; then
    wget -c -O "$MODEL_PATH" "$MODEL_URL"
  else
    die "Neither curl nor wget is available to download the model."
  fi
  [ -s "$MODEL_PATH" ] || die "Download produced an empty file: $MODEL_PATH"
fi

# --- build ------------------------------------------------------------------
info "Building guard with features: $GUARD_FEATURES (release)"
cargo build --release -p ctp-guard --features "$GUARD_FEATURES"

info "Building orchestrator and bench client (release)"
cargo build --release -p ctp-orchestrator
cargo build --release -p ctp-orchestrator --example bench_client

# --- config -----------------------------------------------------------------
info "Writing test config -> $CONFIG_OUT"
abs_model="$(cd "$(dirname "$MODEL_PATH")" && pwd)/$(basename "$MODEL_PATH")"
sed \
  -e 's|^backend = "mock"|backend = "llama"|' \
  -e "s|^socket_path = .*|socket_path = \"$SOCKET_PATH\"|" \
  -e "s|^# model_path = .*|model_path = \"$abs_model\"|" \
  "$REPO_ROOT/ctp.toml.example" > "$CONFIG_OUT"

info "Done."
echo
echo "  Model:   $abs_model"
echo "  Config:  $CONFIG_OUT"
echo "  Socket:  $SOCKET_PATH"
echo
echo "Run the benchmark with:  ./scripts/bench.sh"
