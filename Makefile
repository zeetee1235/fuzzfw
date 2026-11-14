# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 fuzzfw contributors
# Build the fuzzfw CLI without external code generation.
BINARY ?= fuzzfw
GO ?= go
VERSION ?= 0.1.0-dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS = -s -w \
	-X github.com/fuzzfw/fuzzfw/internal/version.Version=$(VERSION) \
	-X github.com/fuzzfw/fuzzfw/internal/version.Commit=$(COMMIT) \
	-X github.com/fuzzfw/fuzzfw/internal/version.BuildDate=$(DATE) \
	-X github.com/fuzzfw/fuzzfw/internal/version.Builder=make

.PHONY: all build test test-unit test-integration lint fmt vet analyzer analyzer-clean sbom dist examples clean help

all: build

help:
	@echo "Targets:"
	@echo "  build             Build ./fuzzfw"
	@echo "  test              Run Go tests"
	@echo "  test-integration  Run native integration tests"
	@echo "  lint              gofmt, go vet, and SPDX header check"
	@echo "  fmt               gofmt the tree"
	@echo "  analyzer          Build native Clang/LLVM analyzers (requires LLVM dev)"
	@echo "  sbom              Generate CycloneDX SBOM"
	@echo "  dist              Build release binary, checksums, and SBOM"
	@echo "  examples          Run example projects"
	@echo "  clean             Remove generated artifacts"

build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/fuzzfw

test:
	$(GO) test ./...

test-unit:
	$(GO) test ./internal/... ./runtime/...

test-integration:
	$(GO) test -tags=integration ./tests/integration/...

lint:
	@test -z "$$(gofmt -l cmd internal runtime tests tools 2>/dev/null)" || (echo "gofmt required:"; gofmt -l cmd internal runtime tests tools; exit 1)
	$(GO) vet ./...
	$(GO) run ./tools/check_headers

fmt:
	gofmt -w cmd internal runtime tests tools

vet:
	$(GO) vet ./...

analyzer:
	cmake -S analyzer -B analyzer/build -G Ninja -DCMAKE_BUILD_TYPE=Release
	cmake --build analyzer/build

analyzer-clean:
	rm -rf analyzer/build

sbom:
	$(GO) run ./tools/sbom --output dist

dist: build sbom
	@mkdir -p dist
	cp $(BINARY) dist/fuzzfw-$(VERSION)-$$(go env GOOS)-$$(go env GOARCH)
	cp LICENSE NOTICE THIRD_PARTY_NOTICES.md dist/
	cd dist && sha256sum fuzzfw-$(VERSION)-$$(go env GOOS)-$$(go env GOARCH) > fuzzfw-$(VERSION)-$$(go env GOOS)-$$(go env GOARCH).sha256

examples:
	$(GO) run ./tools/run_examples

clean:
	rm -rf fuzzfw dist .fuzzfw fuzzfw-out fuzzfw-out-* analyzer/build
	find . -name '*.tmp' -delete
