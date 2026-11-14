#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 fuzzfw contributors
#
# Install a pinned fuzzfw release artifact. Replace the placeholder base URL
# with the company release host before distribution.
set -eu

VERSION="${FUZZFW_VERSION:-0.1.0-dev}"
PREFIX="${FUZZFW_PREFIX:-/usr/local}"
BASE_URL="${FUZZFW_BASE_URL:-https://github.com/fuzzfw/fuzzfw/releases/download}"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

ASSET="fuzzfw-${VERSION}-${OS}-${ARCH}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -fsSL "${BASE_URL}/v${VERSION}/${ASSET}" -o "${TMP}/${ASSET}"
curl -fsSL "${BASE_URL}/v${VERSION}/${ASSET}.sha256" -o "${TMP}/${ASSET}.sha256"
(cd "$TMP" && sha256sum -c "${ASSET}.sha256")
install -m 0755 "${TMP}/${ASSET}" "${PREFIX}/bin/fuzzfw"
echo "installed ${PREFIX}/bin/fuzzfw (${ASSET})"
