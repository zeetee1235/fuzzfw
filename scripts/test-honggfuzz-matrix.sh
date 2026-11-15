#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Operator-run honggfuzz version matrix. Requires network access and the
# honggfuzz build dependencies (binutils-devel and libunwind-ptrace headers on
# Linux). The repository's normal test suite uses the toolchain already on PATH.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
refs="${HFUZZ_REFS:-940b958dfeb6f9131fd846cae31fcc0fe996ae98 83a8415a372d84dcc69ac1e2c2f152190bcf76d1}"
jobs="${JOBS:-4}"

for ref in $refs; do
    work="/tmp/fuzzfw-honggfuzz-$ref"
    rm -rf "$work"
    git clone --quiet https://github.com/google/honggfuzz.git "$work"
    git -C "$work" checkout --quiet "$ref"
    if ! make -C "$work" -j"$jobs" BUILD_LINUX_NO_BFD=true; then
        echo "honggfuzz $ref build failed; install binutils-devel and libunwind-ptrace headers" >&2
        exit 1
    fi
    (
        cd "$repo_root"
        PATH="$work:$work/hfuzz_cc:$PATH" \
            go test -tags='integration honggfuzz' ./tests/integration/...
    )
    echo "honggfuzz $ref: pass"
done
