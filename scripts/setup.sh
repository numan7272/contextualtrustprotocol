#!/usr/bin/env bash
# CTP setup: check dependencies, fetch a GGUF model, build the llama-backed
# guard plus the orchestrator and bench client, and write a local test config.
# One command to get from a fresh Linux install to a runnable end-to-end
# benchmark. Works on any Linux with bash (Ubuntu, Debian, Fedora, Arch,
# openSUSE, Alpine, and WSL2); the dependency hints adapt to your package
# manager.
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
# Detect the package manager so hints fit the distro, not just Debian/Ubuntu.
PM=""
for cand in apt-get dnf pacman zypper apk; do
  if command -v "$cand" >/dev/null 2>&1; then PM="$cand"; break; fi
done

pm_install() { # packages... -> a copy-pasteable install command
  case "$PM" in
    apt-get) echo "sudo apt-get install -y $*" ;;
    dnf)     echo "sudo dnf install -y $*" ;;
    pacman)  echo "sudo pacman -S --needed $*" ;;
    zypper)  echo "sudo zypper install -y $*" ;;
    apk)     echo "sudo apk add $*" ;;
    *)       echo "install with your package manager: $*" ;;
  esac
}

pkg_for() { # logical dep -> package name(s) for the detected manager
  case "$1:$PM" in
    clang:apt-get)     echo "libclang-dev clang" ;;
    clang:dnf)         echo "clang-devel" ;;
    clang:pacman)      echo "clang" ;;
    clang:zypper)      echo "clang-devel" ;;
    clang:apk)         echo "clang-dev" ;;
    clang:*)           echo "libclang/clang development package" ;;
    toolchain:apt-get) echo "build-essential" ;;
    toolchain:dnf)     echo "gcc gcc-c++ make" ;;
    toolchain:pacman)  echo "base-devel" ;;
    toolchain:zypper)  echo "gcc gcc-c++ make" ;;
    toolchain:apk)     echo "build-base" ;;
    toolchain:*)       echo "a C/C++ compiler and make" ;;
    cmake:*)           echo "cmake" ;;
  esac
}

info "Checking dependencies"
missing=0

if ! command -v cargo >/dev/null 2>&1; then
  warn "Rust/cargo not found. Install: https://rustup.rs"
  missing=1
fi
if ! command -v cmake >/dev/null 2>&1; then
  warn "cmake not found. Install: $(pm_install "$(pkg_for cmake)")"
  missing=1
fi
# A C/C++ compiler and make are needed for the native llama.cpp build.
if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
  warn "no C compiler found. Install: $(pm_install "$(pkg_for toolchain)")"
  missing=1
fi
if ! command -v c++ >/dev/null 2>&1 && ! command -v g++ >/dev/null 2>&1; then
  warn "no C++ compiler found. Install: $(pm_install "$(pkg_for toolchain)")"
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
  warn "libclang not found. Install: $(pm_install "$(pkg_for clang)")"
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
