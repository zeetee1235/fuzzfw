#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Zero-config demo: no fuzzfw.toml, no manual build step.
# fuzzfw auto-configures CMake, discovers ready targets, and starts libFuzzer.
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
FUZZFW="${FUZZFW:-../../fuzzfw}"

exec "$FUZZFW" check --time "${FUZZFW_TIME:-30s}" "$@"
