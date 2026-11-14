# Development

## Layout

```text
cmd/fuzzfw/              CLI entry point
internal/cli/            command parsing and orchestration
internal/config/         TOML schema and path validation
internal/compdb/         compilation database import
internal/manifest/       reproducible build manifest
internal/analyzer/       analysis contract, AST-JSON/IR fallback, native runner
internal/planner/        roles, dependencies, classification, evidence
internal/harness/        canonical harness plan and C/C++ emitter
internal/hostbuild/      original TU compilation, link, self-test
internal/engine/         external engine adapters
internal/triage/         replay, classification, minimization, baseline
internal/report/         summary, JUnit, Markdown
internal/toolchain/      tool discovery and capability probes
runtime/replay/          embedded C replay driver
analyzer/clang/          native LibTooling analyzer
analyzer/llvm/           native LLVM IR fact extractor
schemas/                 JSON schemas
tests/                   unit and tagged integration tests
```

## Build and test

```sh
make build
make test
make test-integration
make lint
make analyzer       # optional; requires LLVM/Clang dev headers
```

`make test-integration` requires CMake, Ninja, Clang, and builds fixture
projects. Tests use the native analyzers when present and fall back otherwise.

## Coding rules

- Go: standard library first; `gofmt`, `go vet`; no shell execution outside
  `internal/proc`.
- C/C++: C11/C17, C++17; no exceptions in the replay driver; no signal swallowing.
- Every source file carries an SPDX header (`make lint` checks it).
- JSON artifacts are canonical and schema-versioned. Never change an existing
  field's meaning without bumping the schema.
- New diagnostic codes are additive. Document them in
  `docs/reference/diagnostics.md`.
- No automatic hardware stub, no silent flag/macro removal, no target body
  copying.
- A new target feature must include a deterministic fixture and a fail-closed
  test.

## Adding a fixture

1. Create `tests/fixtures/<name>` with a CMake project and
   `fuzzfw.toml`.
2. Keep the crash seed out of the build self-test seed set when it is intended
   to exercise corpus replay.
3. Add a tagged integration test under `tests/integration`.
4. Run `go test -tags=integration ./tests/integration/...`.

## Native analyzers

Both native tools are read-only and communicate through JSON:

```sh
fuzzfw-analyze --input invocation.json --output fragment.json
fuzzfw-ir-analyze --input module.ll --output facts.json
```

`analyzer/clang/main.cpp` uses Clang LibTooling. `analyzer/llvm/main.cpp` walks
LLVM IR and conservatively tracks argument-derived values. The Go fallback
remains supported so a user can try fuzzfw without LLVM development headers.
Set `FUZZFW_DISABLE_NATIVE=1` to force the fallback in tests or debugging.

To build against a non-standard LLVM installation:

```sh
cmake -S analyzer -B analyzer/build -G Ninja \
  -DLLVM_INCLUDE_DIR=/path/to/llvm/include \
  -DCLANG_INCLUDE_DIR=/path/to/llvm/include \
  -DCLANG_CPP_LIBRARY=/path/to/libclang-cpp.so \
  -DLLVM_LIBRARY=/path/to/libLLVM.so
cmake --build analyzer/build
```

## Release

1. Update `internal/version/version.go`, `CHANGELOG.md`, and package metadata.
2. Run `make lint`, `make test`, `make test-integration`.
3. Build native analyzers on the supported matrix.
4. Run `make dist` and generate the SBOM.
5. Follow `docs/compliance/release-checklist.md`.
6. Tag the source and publish signed checksums and SBOM.

## DCO

Contributions are accepted under the Developer Certificate of Origin. Add a
`Signed-off-by` line to each commit. See [CONTRIBUTING.md](../CONTRIBUTING.md).
