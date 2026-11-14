# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 fuzzfw contributors
#
# Minimal runtime image for building and self-testing host targets.
# honggfuzz is intentionally not baked in; pin and install it separately for
# production fuzzing so its version/license are explicit.
FROM golang:1.23-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=0.1.0-dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/fuzzfw/fuzzfw/internal/version.Version=${VERSION} -X github.com/fuzzfw/fuzzfw/internal/version.Builder=docker" \
    -o /out/fuzzfw ./cmd/fuzzfw

FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
      clang \
      cmake \
      ninja-build \
      git \
      ca-certificates \
      libclang-cpp18 \
      libllvm18 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/fuzzfw /usr/local/bin/fuzzfw
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /usr/share/doc/fuzzfw/

RUN useradd --create-home --uid 10001 fuzz
USER fuzz
WORKDIR /work
ENTRYPOINT ["fuzzfw"]
