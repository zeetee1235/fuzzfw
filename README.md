# fuzzfw

**Deterministic source-level selective host-lifting for embedded C/C++ fuzzing.**

`fuzzfw` analyzes the C/C++ code that actually builds in an embedded project,
replaces only explicitly approved hardware boundaries, links the original
translation units into a Linux host target, verifies that the target function is
really reached, and turns reproduced crashes into CI artifacts.

> Status: **pre-alpha (M0/M1 foundation)**. The core flow works end-to-end on
> Linux x86-64 with Clang. The honggfuzz adapter is implemented but has not yet
> been validated across the release matrix. Read the implemented/not-yet
> implemented table below before relying on a gate.

- No cloud account, API key, telemetry, or network upload.
- No LLM-generated code or automatic "return 0" HAL stubs.
- Compile success is not treated as fuzzability.
- Original translation units are rebuilt and relinked unless an explicit,
  reviewed adapter or user wrapper is provided.
- Every plan, harness, build, and finding is content-hashed and reproducible.

## Why this exists

Embedded parsers and protocol handlers are hard to fuzz on a Linux workstation:
they call UART, DMA, RTOS, MMIO, and vendor HAL APIs. Binary-only rehosting and
random stubbing produce false confidence. `fuzzfw` keeps the product code intact
and makes the hardware boundary explicit, reviewable, and reproducible.

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
                               │ crash artifacts
                    ┌──────────▼──────────┐
                    │ replay/triage/report│
                    │ JSON · JUnit · MD   │
                    └─────────────────────┘
```

The analysis and control planes are separate executables with a versioned JSON
contract. The fuzzing loop contains no Go, Python, RPC, or database.

## Quick start

Requirements: Linux x86-64, Go 1.23+, Clang/LLVM 17+, CMake, Ninja, and a
project that emits `compile_commands.json`.

```sh
git clone <repository>
cd fuzzfw
make build

# Optional: build native Clang/LLVM analyzers.
# The Go fallback remains available when they are absent.
make analyzer

# Build the fixture project.
cd tests/fixtures/c_clean
cmake -S . -B build -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build

# Full CI gate with corpus replay only.
../../../fuzzfw check --engine replay --time 1s --output fuzzfw-out
```

A clean target exits `0`. The intentional bug fixture exits `1`:

```sh
cd ../c_parser
cmake -S . -B build -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build
../../../fuzzfw check --engine replay --time 1s --output fuzzfw-out
# status=fail exit=1, finding in fuzzfw-out/findings/<id>/
```

For actual mutation, use `--engine libfuzzer` (verified in the development
environment) or `--engine honggfuzz` once the honggfuzz toolchain is installed.

## Commands

| Command | Purpose |
|---|---|
| `fuzzfw doctor` | Check Clang, sanitizer support, analyzers, and engine availability. |
| `fuzzfw scan .` | Import build metadata and analyze functions into `.fuzzfw/analysis.json`. |
| `fuzzfw plan --target NAME` | Produce a deterministic host-lift plan and evidence. |
| `fuzzfw build --target NAME` | Generate the harness, compile original TUs, and self-test. |
| `fuzzfw fuzz --time 10m` | Run a built target in an external engine and triage findings. |
| `fuzzfw check --time 10m` | Self-contained CI gate: analyze, build, replay, fuzz, report. |
| `fuzzfw replay FINDING_DIR` | Re-run one finding in a fresh process. |
| `fuzzfw report --input fuzzfw-out/` | Re-render Markdown, JSON, or JUnit output. |
| `fuzzfw inspect --target NAME` | Show roles, constraints, adapters, and diagnostics. |

Exit codes are stable: `0` pass, `1` new host-reproduced target finding, `2`
build/environment/self-test failure or incomplete required check, `3` invalid
configuration or usage.

## Configuration

```toml
schema_version = 1

[project]
name = "sensor-firmware"
source = "."
compdb = "build/compile_commands.json"

[host]
triple = "x86_64-unknown-linux-gnu"
clang = "clang"
clangxx = "clang++"

[ci]
engine = "honggfuzz"      # or libfuzzer / replay
time_seconds = 600
jobs = 2
fail_on_new_reproduced = true
incomplete_is_failure = true

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

See [configuration reference](docs/reference/configuration.md) and
[harness synthesis](docs/harness-synthesis.md).

## What is implemented

| Area | State |
|---|---|
| Go CLI, TOML config, stable exit codes, JSON/JUnit/Markdown | Implemented |
| Compilation database import, build variants, source hashes, Git provenance | Implemented |
| Deterministic C/C++ harness generation for bytes+length APIs | Implemented |
| Original TU host build, sanitizers, sanitizer coverage, replay driver | Implemented |
| Entry reachability, repeated stability, corpus replay, finding reproduction | Implemented |
| Approved HAL adapter contract and prototype check | Implemented |
| User wrapper escape hatch (`void wrapper(const uint8_t *, size_t)`) | Implemented |
| C++ free functions in headers/namespaces | Implemented |
| C++ methods, object factories, RAII lifetime plans | Not yet (P1/P2) |
| Native Clang LibTooling AST analyzer | Implemented, build-tested |
| Native read-only LLVM IR fact extractor | Implemented, build-tested |
| Go AST-JSON/IR fallback when native analyzers are absent | Implemented |
| libFuzzer engine adapter | Implemented, integration-tested |
| honggfuzz engine adapter | Implemented, **not yet release-validated** |
| Persistent execution, DMA/ISR/RTOS event models | Not yet |
| New PM AA/MemorySSA-assisted IR analysis | Not yet |
| Existing unit-test setup extraction | Not yet |
| Multi-target parallel scheduling | Not yet (sequential, bounded) |
| Web UI, central server, custom coverage engine | Explicit non-goals |

## Safety and honesty

`fuzzfw` fails closed on unknown roles, missing headers, unapproved external
symbols, direct MMIO, inline assembly, DMA, RTOS dependence, unresolved function
pointers, and ABI-sensitive layouts. A host ASan finding is evidence about the
host-recompiled code, not automatic proof that the same defect exists on the
MCU. Findings are marked `HOST_ONLY` unless a separate device test confirms them.

Do not run untrusted pull-request code on a privileged self-hosted runner. See
[SECURITY.md](SECURITY.md) and [security model](docs/security-model.md).

## Repository layout

```text
cmd/fuzzfw/              Go CLI entry point
internal/                Go control plane (config, analysis, planner, harness,
                         host build, engine, triage, report)
analyzer/clang/          Clang LibTooling AST analyzer (C++17)
analyzer/llvm/           read-only LLVM IR fact extractor (C++17)
runtime/replay/          embedded one-input replay driver (C)
schemas/                 versioned JSON schemas
docs/                    architecture, reference, ADRs, compliance
examples/                runnable C/C++ examples
tests/fixtures/          deterministic integration fixtures
tools/                   SBOM, header check, example runner
```

## Licensing and commercial use

The project is licensed under **Apache-2.0**, which permits commercial use,
modification, redistribution, and sale, provided the license and NOTICE
requirements are met. Optional external tools such as LLVM/Clang and honggfuzz
are invoked as separate programs and keep their own licenses. See
[LICENSE](LICENSE), [NOTICE](NOTICE), [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md),
and [compliance guidance](docs/compliance/licensing.md).

`fuzzfw` is a working product name. No trademark registration is claimed.
Copyright currently belongs to the fuzzfw contributors; update `NOTICE`,
`AUTHORS.md`, and the copyright holder before a company software registration or
commercial release.

## Documentation

- [Architecture](docs/architecture.md)
- [Quick start](docs/guides/quickstart.md)
- [Configuration](docs/reference/configuration.md)
- [CLI reference](docs/reference/cli.md)
- [Harness synthesis](docs/harness-synthesis.md)
- [Compatibility matrix](docs/compatibility.md)
- [CI integration](docs/ci-integration.md)
- [Diagnostics](docs/reference/diagnostics.md)
- [Development](docs/development.md)
- [Roadmap](docs/roadmap.md)
- [Commercial and compliance notes](docs/compliance/README.md)

## 한국어 요약

`fuzzfw`는 임베디드 C/C++ 펌웨어의 **실제 컴파일되는 코드**를 분석하고, 승인된
HAL 경계만 교체해 Linux에서 실행 가능한 퍼징 타깃을 만드는 도구입니다. Go가
CLI·계획·빌드·CI를 담당하고, C++ Clang/LLVM 분석기와 C 리플레이 런타임이 실제
네이티브 경로를 구성합니다. Python 런타임, 클라우드, LLM, 텔레메트리는 사용하지
않습니다.

현재는 M0/M1 기반이 동작합니다. `check`는 분석→계획→호스트 빌드→도달성/입력
사용/안정성 검사→corpus 재생→퍼징→재현/보고를 수행하며, 재현된 타깃 결함은
exit `1`, 필수 검사 미완료는 exit `2`로 구분합니다. C++ 객체 수명, DMA/ISR/RTOS
모델, persistent 모드, New PM 정밀 분석은 아직 구현 범위가 아닙니다.

자세한 한국어 안내는 [README.ko.md](README.ko.md)를 참고하세요.
