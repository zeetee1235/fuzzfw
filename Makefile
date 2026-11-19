# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 fuzzfw contributors
#
# Core developer commands. Keep the surface small; product gates live in the
# CLI, not in this Makefile.

BINARY ?= fuzzfw
GO ?= go
VERSION ?= 0.0.1
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS = -s -w \
	-X github.com/fuzzfw/fuzzfw/internal/version.Version=$(VERSION) \
	-X github.com/fuzzfw/fuzzfw/internal/version.Commit=$(COMMIT) \
	-X github.com/fuzzfw/fuzzfw/internal/version.BuildDate=$(DATE) \
	-X github.com/fuzzfw/fuzzfw/internal/version.Builder=make

.PHONY: all build test test-integration lint fmt vet analyzer analyzer-clean clean help dist

all: build

help:
	@echo "Targets:"
	@echo "  build             Build ./fuzzfw"
	@echo "  test              Run Go unit tests"
	@echo "  test-integration  Run native fixture tests"
	@echo "  lint              gofmt check + go vet"
	@echo "  fmt               gofmt the tree"
	@echo "  analyzer          Build native Clang/LLVM analyzers"
	@echo "  dist              Build a Linux release archive (VERSION=)"
	@echo "  clean             Remove generated artifacts"

build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/fuzzfw

test:
	$(GO) test ./...

test-integration:
	$(GO) test -tags=integration ./tests/integration/...

lint:
	@test -z "$$(gofmt -l cmd internal runtime tests 2>/dev/null)" || (echo "gofmt required:"; gofmt -l cmd internal runtime tests; exit 1)
	$(GO) vet ./...

fmt:
	gofmt -w cmd internal runtime tests

vet:
	$(GO) vet ./...

analyzer:
	cmake -S analyzer -B analyzer/build -G Ninja -DCMAKE_BUILD_TYPE=Release
	cmake --build analyzer/build

dist:
	./scripts/package-release.sh $(VERSION)

analyzer-clean:
	rm -rf analyzer/build

clean:
	rm -rf fuzzfw dist analyzer/build .fuzzfw fuzzfw-out fuzzfw-out-*
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find examples tests/fixtures tests/pilots -type d -name .fuzzfw -prune -exec rm -rf {} +
	find examples tests/fixtures tests/pilots -type d -name fuzzfw-out -prune -exec rm -rf {} +
	find examples tests/fixtures tests/pilots -type d -name build -prune -exec rm -rf {} +
