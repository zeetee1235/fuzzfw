#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# One-shot README smoke test.
#
# Installs the host dependencies with the native package manager when possible,
# builds fuzzfw, and runs every runnable example from README.md. Each case has an
# expected exit code; the script prints a final PASS/FAIL/SKIP table and keeps
# all logs and generated artifacts for inspection.
#
# Usage:
#   ./scripts/quickstart.sh                 # install deps (if needed), run all
#   ./scripts/quickstart.sh --no-install    # do not touch the package manager
#   ./scripts/quickstart.sh --skip-integration
#   ./scripts/quickstart.sh --skip-analyzer
#   ./scripts/quickstart.sh --help
#
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
FUZZFW="$ROOT/fuzzfw"
OUT_ROOT="$ROOT/fuzzfw-out-readme"
LOG_DIR="$OUT_ROOT/logs"
INSTALL_DEPS=1
RUN_INTEGRATION=1
RUN_ANALYZER=1

usage() {
    cat <<'EOF'
Usage: ./scripts/quickstart.sh [options]

Installs host dependencies when needed, builds fuzzfw, and runs every runnable
README example with its expected exit code.

Options:
  --no-install         Do not call the package manager
  --skip-integration   Skip the integration test suite
  --skip-analyzer      Skip the optional native analyzer build
  -h, --help           Show this help

Logs and outputs are kept in fuzzfw-out-readme/.
EOF
}

while (($# > 0)); do
    case "$1" in
        --no-install) INSTALL_DEPS=0 ;;
        --skip-integration) RUN_INTEGRATION=0 ;;
        --skip-analyzer) RUN_ANALYZER=0 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 3 ;;
    esac
    shift
done

if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'
else
    C_RESET=; C_BOLD=; C_RED=; C_GREEN=; C_YELLOW=; C_BLUE=
fi

log()  { printf '%s[readme]%s %s\n' "$C_BLUE" "$C_RESET" "$*"; }
pass() { printf '%s[PASS]%s %s\n'   "$C_GREEN" "$C_RESET" "$*"; }
fail() { printf '%s[FAIL]%s %s\n'   "$C_RED"   "$C_RESET" "$*"; }
skip() { printf '%s[SKIP]%s %s\n'   "$C_YELLOW" "$C_RESET" "$*"; }

# Go writes temporary build files to TMPDIR. Small tmpfs mounts and per-user
# quotas are common on CI hosts, so prefer a cache directory under $HOME.
if [[ -z "${FUZZFW_TMPDIR:-}" ]]; then
    FUZZFW_TMPDIR="${XDG_CACHE_HOME:-$HOME/.cache}/fuzzfw/tmp"
fi
mkdir -p "$FUZZFW_TMPDIR"
export TMPDIR="$FUZZFW_TMPDIR"

mkdir -p "$LOG_DIR"
printf 'fuzzfw README smoke test\nroot: %s\nlogs: %s\n\n' "$ROOT" "$LOG_DIR"

AS_ROOT=()
if [[ "$(id -u)" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
        AS_ROOT=(sudo)
    fi
fi

os_id() {
    local id="" like=""
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        id="${ID:-}"; like="${ID_LIKE:-}"
    fi
    printf '%s %s\n' "$id" "$like"
}

install_packages() {
    local id_like pm
    id_like="$(os_id)"

    if command -v apt-get >/dev/null 2>&1; then
        pm=apt
    elif command -v dnf >/dev/null 2>&1; then
        pm=dnf
    elif command -v yum >/dev/null 2>&1; then
        pm=yum
    elif command -v pacman >/dev/null 2>&1; then
        pm=pacman
    elif command -v zypper >/dev/null 2>&1; then
        pm=zypper
    elif command -v apk >/dev/null 2>&1; then
        pm=apk
    else
        fail "no supported package manager found (apt/dnf/yum/pacman/zypper/apk)"
        return 1
    fi

    log "installing dependencies with $pm ($id_like)"
    case "$pm" in
        apt)
            "${AS_ROOT[@]}" apt-get update -y
            DEBIAN_FRONTEND=noninteractive "${AS_ROOT[@]}" apt-get install -y \
                build-essential clang cmake ninja-build git make curl ca-certificates \
                golang-go libclang-dev llvm-dev pkg-config \
                zlib1g-dev libzstd-dev libxml2-dev libedit-dev libffi-dev
            ;;
        dnf|yum)
            "${AS_ROOT[@]}" "$pm" install -y \
                gcc gcc-c++ clang clang-devel llvm-devel cmake ninja-build git make curl \
                golang zlib-devel libzstd-devel libxml2-devel libedit-devel libffi-devel
            ;;
        pacman)
            "${AS_ROOT[@]}" pacman -Sy --needed --noconfirm \
                base-devel clang cmake ninja git make curl go \
                zlib zstd libxml2 libedit libffi
            ;;
        zypper)
            "${AS_ROOT[@]}" zypper --non-interactive install \
                gcc gcc-c++ clang clang-devel llvm-devel cmake ninja git make curl \
                go zlib-devel libzstd-devel libxml2-devel libedit-devel libffi-devel
            ;;
        apk)
            "${AS_ROOT[@]}" apk add --no-cache \
                build-base clang clang-dev llvm-dev cmake ninja git make curl go \
                zlib-dev zstd-dev libxml2-dev libedit-dev libffi-dev
            ;;
    esac
}

go_minor() {
    go version 2>/dev/null | sed -E 's/.* go([0-9]+)\.([0-9]+).*/\1 \2/' || true
}

go_is_new_enough() {
    local major minor
    read -r major minor <<<"$(go_minor)"
    [[ -n "${major:-}" && -n "${minor:-}" ]] || return 1
    (( major > 1 || (major == 1 && minor >= 23) ))
}

install_go_tarball() {
    local arch version url tmp
    case "$(uname -m)" in
        x86_64|amd64) arch=amd64 ;;
        aarch64|arm64) arch=arm64 ;;
        *) fail "unsupported Go download architecture: $(uname -m)"; return 1 ;;
    esac

    version="$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -1)"
    [[ -n "$version" ]] || { fail "could not determine latest Go version"; return 1; }
    url="https://go.dev/dl/${version}.linux-${arch}.tar.gz"
    tmp="${FUZZFW_TMPDIR}/go-download"
    rm -rf "$tmp" "${HOME}/.local/go-fuzzfw"
    mkdir -p "$tmp" "${HOME}/.local"
    log "installing $version to ${HOME}/.local/go-fuzzfw"
    curl -fsSL "$url" -o "$tmp/go.tar.gz"
    tar -C "$tmp" -xzf "$tmp/go.tar.gz"
    mv "$tmp/go" "${HOME}/.local/go-fuzzfw"
    export PATH="${HOME}/.local/go-fuzzfw/bin:$PATH"
}

ensure_go() {
    if go_is_new_enough; then
        return 0
    fi
    log "Go 1.23+ is required; installing a local toolchain"
    install_go_tarball
    go_is_new_enough || { fail "Go installation did not produce a usable toolchain"; return 1; }
}

check_tools() {
    local missing=0 t
    for t in go clang clang++ cmake ninja make git; do
        if ! command -v "$t" >/dev/null 2>&1; then
            fail "missing required tool: $t"
            missing=1
        fi
    done
    if ! command -v llvm-cov >/dev/null 2>&1 || ! command -v llvm-profdata >/dev/null 2>&1; then
        skip "llvm-cov/llvm-profdata not found on PATH; coverage may be versioned (e.g. llvm-cov-18)"
    fi
    (( missing == 0 ))
}

run_case() {
    local name="$1" expected="$2" workdir="$3"
    shift 3
    local log_file="$LOG_DIR/$name.log" rc
    set +e
    ( cd "$workdir" && "$@" ) >"$log_file" 2>&1
    rc=$?
    set -e
    if [[ "$rc" -eq "$expected" ]]; then
        pass "$name (exit $rc, expected $expected)"
        printf '%-28s %-8s %-8s %-6s %s\n' "$name" "$expected" "$rc" "PASS" "$log_file" >>"$OUT_ROOT/results.tsv"
        return 0
    fi
    fail "$name (exit $rc, expected $expected) -> $log_file"
    printf '%-28s %-8s %-8s %-6s %s\n' "$name" "$expected" "$rc" "FAIL" "$log_file" >>"$OUT_ROOT/results.tsv"
    tail -n 25 "$log_file" | sed 's/^/    /' >&2
    return 1
}

run_optional() {
    local name="$1" workdir="$2"
    shift 2
    local log_file="$LOG_DIR/$name.log" rc
    set +e
    ( cd "$workdir" && "$@" ) >"$log_file" 2>&1
    rc=$?
    set -e
    if [[ "$rc" -eq 0 ]]; then
        pass "$name (optional)"
        printf '%-28s %-8s %-8s %-6s %s\n' "$name" "0" "$rc" "PASS" "$log_file" >>"$OUT_ROOT/results.tsv"
    else
        skip "$name (optional, exit $rc) -> $log_file"
        printf '%-28s %-8s %-8s %-6s %s\n' "$name" "0" "$rc" "SKIP" "$log_file" >>"$OUT_ROOT/results.tsv"
    fi
}

FAILURES=0
trap 'rc=$?; if (( rc != 0 )); then echo "unexpected failure at line $LINENO (exit $rc)" >&2; fi' ERR

: >"$OUT_ROOT/results.tsv"

if (( INSTALL_DEPS )); then
    need_install=0
    for t in clang clang++ cmake ninja make git; do
        command -v "$t" >/dev/null 2>&1 || need_install=1
    done
    go_is_new_enough || need_install=1
    if (( need_install )); then
        if [[ "$(id -u)" -ne 0 ]]; then
            if ! command -v sudo >/dev/null 2>&1; then
                fail "dependencies are missing and sudo is unavailable; install them manually or run as root"
                exit 2
            fi
            log "using sudo for dependency installation"
        fi
        install_packages
    fi
    ensure_go
else
    log "--no-install: skipping package manager"
    if ! go_is_new_enough; then
        fail "Go 1.23+ is required; rerun without --no-install or install Go manually"
        exit 2
    fi
fi

check_tools || exit 2

log "building fuzzfw"
if ! run_case build 0 "$ROOT" make build; then
    FAILURES=$((FAILURES + 1))
fi
if [[ ! -x "$FUZZFW" ]]; then
    fail "fuzzfw binary was not produced"
    exit 2
fi

run_case version 0 "$ROOT" "$FUZZFW" --version || FAILURES=$((FAILURES + 1))
run_case doctor 0 "$ROOT" "$FUZZFW" doctor || FAILURES=$((FAILURES + 1))

if (( RUN_ANALYZER )); then
    run_optional analyzer "$ROOT" make analyzer
else
    skip "analyzer (disabled with --skip-analyzer)"
    printf '%-28s %-8s %-8s %-6s %s\n' "analyzer" "0" "-" "SKIP" "-" >>"$OUT_ROOT/results.tsv"
fi

CLEAN="$ROOT/tests/fixtures/c_clean"
PARSER="$ROOT/tests/fixtures/c_parser"

log "running c_clean quick start"
run_case c_clean_cmake 0 "$CLEAN" cmake -S . -B build -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON || FAILURES=$((FAILURES + 1))
run_case c_clean_build 0 "$CLEAN" cmake --build build || FAILURES=$((FAILURES + 1))
run_case c_clean_check 0 "$CLEAN" "$FUZZFW" check --engine replay --time 1s --output fuzzfw-out-readme || FAILURES=$((FAILURES + 1))

log "running c_parser quick start (intentional finding)"
run_case c_parser_cmake 0 "$PARSER" cmake -S . -B build -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON || FAILURES=$((FAILURES + 1))
run_case c_parser_build 0 "$PARSER" cmake --build build || FAILURES=$((FAILURES + 1))
run_case c_parser_check 1 "$PARSER" "$FUZZFW" check --engine replay --time 1s --output fuzzfw-out-readme || FAILURES=$((FAILURES + 1))

FINDING_DIR="$(find "$PARSER/fuzzfw-out-readme/findings" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -1 || true)"
if [[ -n "$FINDING_DIR" ]]; then
    run_case c_parser_replay 1 "$PARSER" "$FUZZFW" replay --attempts 3 "$FINDING_DIR" || FAILURES=$((FAILURES + 1))
else
    fail "c_parser produced no finding directory"
    FAILURES=$((FAILURES + 1))
fi

log "running libFuzzer mutation"
run_case c_parser_libfuzzer 1 "$PARSER" "$FUZZFW" check --engine libfuzzer --time 10s --output fuzzfw-out-readme-libfuzzer || FAILURES=$((FAILURES + 1))

log "running zero-config example (auto CMake build + target discovery)"
rm -rf "$ROOT/examples/simple-parser/build" "$ROOT/examples/simple-parser/fuzzfw-out-readme"
run_case zero_config_example 1 "$ROOT/examples/simple-parser" ./run.sh --output fuzzfw-out-readme || FAILURES=$((FAILURES + 1))

log "running Go unit tests"
run_case go_test 0 "$ROOT" go test ./... || FAILURES=$((FAILURES + 1))

if (( RUN_INTEGRATION )); then
    log "running integration tests (this takes about a minute)"
    run_case integration 0 "$ROOT" go test -tags=integration ./tests/integration/... || FAILURES=$((FAILURES + 1))
else
    skip "integration (disabled with --skip-integration)"
    printf '%-28s %-8s %-8s %-6s %s\n' "integration" "0" "-" "SKIP" "-" >>"$OUT_ROOT/results.tsv"
fi

run_case lint 0 "$ROOT" make lint || FAILURES=$((FAILURES + 1))

printf '\n%sSummary%s\n' "$C_BOLD" "$C_RESET"
printf '%-28s %-8s %-8s %-6s %s\n' "CASE" "EXPECTED" "ACTUAL" "RESULT" "LOG"
cat "$OUT_ROOT/results.tsv"

printf '\nArtifacts\n'
printf '  logs:       %s\n' "$LOG_DIR"
printf '  c_clean:    %s\n' "$CLEAN/fuzzfw-out-readme"
printf '  c_parser:   %s\n' "$PARSER/fuzzfw-out-readme"
printf '  libFuzzer:  %s\n' "$PARSER/fuzzfw-out-readme-libfuzzer"
printf '  example:    %s\n' "$ROOT/examples/simple-parser/fuzzfw-out-readme"

if command -v honggfuzz >/dev/null 2>&1; then
    printf '  honggfuzz:  available (not run by this script)\n'
else
    printf '  honggfuzz:  not installed (optional engine; skipped)\n'
fi
printf '  analyzer:   %s\n' "$(command -v fuzzfw-analyze >/dev/null 2>&1 || [[ -x "$ROOT/analyzer/build/fuzzfw-analyze" ]] && echo native || echo fallback)"

if (( FAILURES > 0 )); then
    printf '\n%s%d case(s) failed.%s\n' "$C_RED" "$FAILURES" "$C_RESET" >&2
    exit 1
fi

printf '\n%sAll README examples passed.%s\n' "$C_GREEN" "$C_RESET"
