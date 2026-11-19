#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Build a self-contained Linux release archive:
#   fuzzfw-<version>-linux-amd64/
#     fuzzfw
#     README.md
#     VERSION
#     docs/
#     examples/simple-parser/
#
# Usage: ./scripts/package-release.sh [version]
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-0.0.1}"
GOARCH="${GOARCH:-amd64}"
NAME="fuzzfw-${VERSION}-linux-${GOARCH}"
DIST="$ROOT/dist"
STAGE="$DIST/$NAME"

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]]; then
    echo "invalid semantic version: $VERSION" >&2
    exit 3
fi

mkdir -p "$DIST"
rm -rf "$STAGE"
mkdir -p "$STAGE"

echo "building $NAME"
(
    cd "$ROOT"
    GOOS=linux GOARCH="$GOARCH" make build \
        VERSION="$VERSION" \
        BINARY="$STAGE/fuzzfw"
)

cp "$ROOT/README.md" "$STAGE/README.md"
printf '%s\n' "$VERSION" >"$STAGE/VERSION"
cp -a "$ROOT/docs" "$STAGE/docs"
mkdir -p "$STAGE/examples"
cp -a "$ROOT/examples/simple-parser" "$STAGE/examples/simple-parser"

# The example rebuilds itself on first use; never ship local build products.
find "$STAGE/examples" -type d \( -name build -o -name .fuzzfw -o -name 'fuzzfw-out*' \) -prune -exec rm -rf {} +
find "$STAGE/examples" -type f \( -name 'fuzz-*.log' -o -name '*.o' \) -delete

tar -C "$DIST" -czf "$DIST/$NAME.tar.gz" "$NAME"
(
    cd "$DIST"
    sha256sum "$NAME.tar.gz" >"$NAME.tar.gz.sha256"
)

printf '\nrelease artifacts:\n'
ls -lh "$DIST/$NAME.tar.gz" "$DIST/$NAME.tar.gz.sha256"
printf '\nsha256:\n'
cat "$DIST/$NAME.tar.gz.sha256"
