# fuzzfw

**Deterministic source-level selective host-lifting for embedded C/C++ fuzzing.**

`fuzzfw` analyzes the C/C++ code that actually compiles in an embedded project,
replaces only explicitly approved hardware boundaries, links the original
translation units into a Linux host target, verifies that the target function is
really reached and consumes input, and turns reproduced crashes into replayable
artifacts.

> Status: **pre-alpha (M0/M1 foundation)**. The core flow works end-to-end on
> Linux x86-64 with Clang. libFuzzer and honggfuzz have been exercised end-to-end.

## What it does

```text
C/C++ project + compile_commands.json + fuzzfw.toml
                         │
        ┌────────────────▼─────────────────┐
        │ Go control plane                 │
        │ build import · planner · harness │
        │ host build · engine · triage     │
        └───────┬──────────────┬───────────┘
                │ JSON         │ argv (never a shell)
        ┌───────▼──────┐  ┌────▼──────────────┐
        │ C++ analyzers│  │ Clang host build   │
        │ Clang AST    │  │ original TUs       │
        │ LLVM IR      │  │ approved adapters  │
        └──────────────┘  └────┬──────────────┘
                               │
                    ┌──────────▼──────────┐
                    │ native fuzz target  │
                    │ ASan/UBSan + engine │
                    └──────────┬──────────┘
                               │ artifacts
                    ┌──────────▼──────────┐
                    │ replay/triage/report│
                    │ JSON · JUnit · MD   │
                    └─────────────────────┘
```

Key behavior:

- Original translation units are rebuilt and relinked, not copied or rewritten.
- No automatic `return 0` / `NULL` HAL stubs.
- Compile success is not treated as fuzzability.
- Target reachability, input use, stability, and reproduction are separate gates.
- Findings are `HOST_ONLY` unless separately confirmed on a device.
- No cloud, telemetry, Python runtime, LLM, or network upload.

## Requirements

- Linux x86-64
- Go 1.23+
- Clang/LLVM 17+ with ASan/UBSan
- CMake and Ninja for CMake projects
- Optional: LLVM/Clang development headers for native analyzers
- Optional: honggfuzz for the honggfuzz adapter

## Build

```sh
make build
./fuzzfw doctor

# Optional native analyzers; the Go AST-JSON/textual-IR fallback remains.
make analyzer
```

## Quick start

```sh
cd tests/fixtures/c_clean
cmake -S . -B build -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build
../../../fuzzfw check --engine replay --time 1s --output fuzzfw-out
```

A clean target exits `0`. The intentional bug fixture exits `1`:

```sh
cd ../c_parser
cmake -S . -B build -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build
../../../fuzzfw check --engine replay --time 1s --output fuzzfw-out
# fuzzfw-out/findings/<id>/input.bin, finding.json, sanitizer.log, replay.sh
```

For mutation, use `--engine libfuzzer` (tested) or `--engine honggfuzz` when the
engine is installed.

## Commands

| Command | Purpose |
|---|---|
| `doctor` | Check Clang, sanitizers, analyzers, and engines. |
| `scan` | Import compdb and analyze functions into `.fuzzfw/analysis.json`. |
| `plan` | Produce a deterministic host-lift plan with evidence. |
| `build` | Generate a harness, compile original TUs, and self-test. |
| `fuzz` | Run a built target in an external engine and triage findings. |
| `check` | Self-contained CI gate: analyze, build, replay, fuzz, report. |
| `replay` | Re-run one finding input in a fresh process. |
| `report` | Re-render Markdown, JSON, or JUnit output. |
| `inspect` | Show roles, constraints, adapters, and diagnostics. |

Exit codes: `0` pass, `1` new host-reproduced target finding, `2`
build/environment/self-test failure or incomplete required check, `3` invalid
configuration or usage.

## Configuration

```toml
schema_version = 1

[project]
name = "sensor-firmware"
source = "."
compdb = "build/compile_commands.json"

[ci]
engine = "honggfuzz"
time_seconds = 600
jobs = 2

[[targets]]
name = "sensor_decode"
symbol = "sensor_decode"
source = "src/sensor.c"
header = "include/sensor.h"
input = "bytes_length"
required = true
max_input_bytes = 4096
seeds = ["tests/fuzzfw/seeds"]

[[adapters]]
original_symbol = "HAL_UART_Receive"
replacement_source = "tests/fuzzfw/adapters/uart.c"
contract = "tests/fuzzfw/contracts/uart.json"
```

See [configuration](docs/reference/configuration.md) and
[harness synthesis](docs/harness-synthesis.md).

## Implemented

- Go CLI, strict TOML, stable exit codes, JSON/JUnit/Markdown.
- Compilation database import, build variants, source hashes, Git provenance.
- Native Clang LibTooling AST analyzer and read-only LLVM IR fact extractor.
- Go AST-JSON/textual-IR fallback with explicit reduced evidence.
- Deterministic C/C++ harness generation for bytes+length APIs.
- Original TU host build with ASan/UBSan, coverage, entry reachability,
  input-use evidence, stability, corpus replay, and finding reproduction.
- Adapter contracts and user wrapper escape hatch.
- C context objects with explicit init/reset/destroy lifecycle.
- Explicit output buffers with configured capacity and overrun detection.
- Post-call return/output invariant hooks that become triaged
  `target_invariant` findings.
- Per-target corpus quality metrics for replayed inputs, executed frames, and
  distinct observed states.
- Length-prefixed multi-frame sequences with bounded per-frame target calls,
  state probing, per-frame reset hooks, and recorded state hashes.
- Deterministic command/magic-constant dictionaries passed to libFuzzer and
  honggfuzz.
- Conservative local-call interprocedural IR argument-use propagation.
- Optional integer/implicit-conversion/local-bounds sanitizer profiles.
- C++ free functions/namespaces and member functions through explicit
  factory/RAII paths (value, reference with external lifetime, raw pointer +
  destroy, `unique_ptr`, `shared_ptr`).
- libFuzzer and honggfuzz adapters end-to-end tested.
- IR loop-bound/data-dependence evidence and compare-constant facts.
- Finding minimization and baseline bootstrap.
- Persistent reset probe: identical input repeated in one process must produce
  identical coverage; otherwise `E_STATE_LEAK`.
- Approved DMA/ISR/RTOS event models with an adapter-visible input stream and
  explicit before/after event hooks.
- Native AA/MemorySSA evidence: pointer alias facts and memory-access counts,
  plus loop-bound and compare-constant facts.
- C++ reference-returning factories with explicit external-lifetime review.

## Not yet

- Arbitrary C++ constructors and automatic object-graph synthesis; complex
  graphs must go through an explicit factory or wrapper.
- Full RTOS scheduler emulation; only approved event adapters/hooks are supported.
- Whole-program points-to analysis and deeper interprocedural alias reasoning.
- Existing unit-test context extraction.
- Multi-target parallel scheduling.
- honggfuzz validation across a wider release matrix.

## Repository layout

```text
cmd/fuzzfw/              CLI entry point
internal/                Go control plane
analyzer/clang/          C++ LibTooling AST analyzer
analyzer/llvm/           C++ read-only LLVM IR analyzer
runtime/replay/          embedded C replay driver
schemas/                 versioned JSON contracts
docs/                    architecture and reference docs
examples/simple-parser/  runnable demo
tests/fixtures/          C/C++/HAL/wrapper/fallback fixtures
```

## Documentation

- [Architecture](docs/architecture.md)
- [Quick start](docs/guides/quickstart.md)
- [Configuration](docs/reference/configuration.md)
- [CLI](docs/reference/cli.md)
- [Harness synthesis](docs/harness-synthesis.md)
- [Compatibility](docs/compatibility.md)
- [Security model](docs/security-model.md)
- [Core parser/protocol plan](docs/core-plan.md)
- [Diagnostics](docs/reference/diagnostics.md)
- [Schemas](docs/reference/schemas.md)

## Test

```sh
go test ./...
go test -tags=integration ./tests/integration/...
make lint

# Optional: requires honggfuzz/hfuzz-clang/hfuzz-clang++ in PATH
# Includes an unseeded discovery test against tests/fixtures/c_vuln.
go test -tags='integration honggfuzz' ./tests/integration/...
```

The discovery test starts with benign seeds only and passes when honggfuzz
produces a new reproducible `target_crash`; it is not based on a pre-seeded
crash file.

## License

Apache-2.0. See [LICENSE](LICENSE).
