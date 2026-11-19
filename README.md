# fuzzfw

Deterministic source-level host-lifting for embedded C/C++ fuzzing.

`fuzzfw` analyzes the C/C++ that actually compiles, replaces only approved
hardware boundaries, relinks the original translation units on Linux, verifies
that the target is reached and consumes input, and turns reproduced crashes into
replayable artifacts.

> Status: pre-alpha. Linux x86-64 with Clang. libFuzzer and honggfuzz are
> supported; honggfuzz is optional.

## What it does

- Rebuilds and relinks original translation units; does not rewrite firmware.
- Requires approved adapters or wrappers instead of automatic `return 0` stubs.
- Gates on compilation, entry reachability, input use, stability, and
  reproduction instead of treating a successful build as fuzzable.
- Reports `HOST_ONLY` findings unless separately confirmed on a device.
- Produces JSON, JUnit, Markdown, replay scripts, and minimized inputs.

## Requirements

- Linux x86-64
- Go 1.23+
- Clang/LLVM 17+ with ASan/UBSan
- CMake and Ninja
- Optional: LLVM/Clang development headers for native analyzers
- Optional: honggfuzz for the honggfuzz engine

## Install a release

```sh
tar xzf fuzzfw-0.0.1-linux-amd64.tar.gz
cd fuzzfw-0.0.1-linux-amd64
./fuzzfw doctor
cd examples/simple-parser
./run.sh
```

The archive contains the binary, documentation, and the zero-config example.
No `fuzzfw.toml` is required for the example.

## Verify everything

The fastest way to check the project is the one-shot script. It installs
dependencies with the native package manager (apt, dnf/yum, pacman, zypper, or
apk), builds fuzzfw, and runs every example below with expected exit codes.

```sh
./scripts/quickstart.sh
```

Useful flags:

```sh
./scripts/quickstart.sh --no-install        # dependencies already installed
./scripts/quickstart.sh --skip-integration  # skip the ~1 minute test suite
./scripts/quickstart.sh --skip-analyzer     # use the Go fallback analyzer
```

The script prints a PASS/FAIL/SKIP table and keeps logs and outputs in
`fuzzfw-out-readme/`. A successful run reports:

| Case | Expected |
|---|---|
| build, version, doctor | exit 0 |
| `c_clean` check | exit 0, no finding |
| `c_parser` check | exit 1, one repo-reproduced finding |
| `c_parser` replay | exit 1, 3/3 reproductions |
| `c_parser` libFuzzer | exit 1, one finding |
| zero-config example | exit 1, mutated crash |
| `go test ./...` | exit 0 |
| integration tests | exit 0 |
| `make lint` | exit 0 |

If `honggfuzz` is not installed the script skips that optional engine. The
native analyzers are also optional; without them fuzzfw uses the Go
AST-JSON/textual-IR fallback.

## Manual quick start

```sh
make build
./fuzzfw doctor

# Native analyzers (optional): clang-devel + llvm-devel required
make analyzer
```

Zero-config example (no `fuzzfw.toml`, no manual build):

```sh
cd examples/simple-parser
./run.sh
# or: ../../fuzzfw check --time 30s
```

fuzzfw auto-configures CMake if needed, discovers ready targets, attaches
`seeds/`, and starts libFuzzer. Expected: exit 1 with one mutated
`address:heap-buffer-overflow` in `fuzzfw-out/findings/`.

Clean fixture:

```sh
cd tests/fixtures/c_clean
cmake -S . -B build -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build
../../../fuzzfw check --engine replay --time 1s --output fuzzfw-out
# exit 0
```

Intentional-bug fixture:

```sh
cd ../c_parser
cmake -S . -B build -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build
../../../fuzzfw check --engine replay --time 1s --output fuzzfw-out
# exit 1
```

`fuzzfw-out/findings/<id>/` contains `input.bin`, `finding.json`,
`sanitizer.log`, `replay.sh`, and `repro.json`.

Replay a finding in a fresh process:

```sh
../../../fuzzfw replay --attempts 3 fuzzfw-out/findings/<id>
```

Run mutation instead of corpus replay:

```sh
../../../fuzzfw check --engine libfuzzer --time 10s --output fuzzfw-out
# or: --engine honggfuzz when installed
```

## Commands

| Command | Purpose |
|---|---|
| `doctor` | Check Clang, sanitizers, analyzers, and engines. |
| `scan` | Import the compilation database and analyze functions. |
| `plan` | Produce a deterministic host-lift plan with evidence. |
| `build` | Generate a harness, compile original TUs, and self-test. |
| `fuzz` | Run a built target in an external engine and triage findings. |
| `check` | Analyze, build, replay, fuzz, and report in one gate. |
| `replay` | Re-run one finding input in a fresh process. |
| `report` | Re-render Markdown, JSON, or JUnit output. |
| `inspect` | Show roles, constraints, adapters, and diagnostics. |

Exit codes: `0` pass, `1` new host-reproduced finding, `2`
build/environment/self-test failure, `3` invalid configuration or usage.

## Configuration

```toml
schema_version = 1

[project]
source = "."
compdb = "build/compile_commands.json"

[ci]
engine = "replay"
time_seconds = 60
jobs = 2

[[targets]]
name = "parse_packet"
symbol = "parse_packet"
source = "src/parser.c"
header = "include/parser.h"
input = "bytes_length"
required = true
max_input_bytes = 4096
seeds = ["tests/fuzzfw/seeds"]
```

Hardware symbols need an approved adapter with a reviewed contract:

```toml
[[adapters]]
original_symbol = "HAL_UART_Receive"
replacement_source = "tests/fuzzfw/adapters/uart.c"
contract = "tests/fuzzfw/contracts/uart.json"
```

See [configuration](docs/reference/configuration.md) and
[harness synthesis](docs/harness-synthesis.md) for all fields and gate rules.

## Output

```text
fuzzfw-out/
├── summary.json, junit.xml, summary.md, diagnostics.json
├── build-info.json
├── corpus/<target>/
└── findings/<id>/
    ├── input.bin
    ├── finding.json
    ├── sanitizer.log
    ├── replay.sh
    └── repro.json
```

## Test

```sh
go test ./...
go test -tags=integration ./tests/integration/...
make lint
```

The integration suite covers the clean, crash, HAL, wrapper, event-model,
state-leak, C++, and fallback fixtures. honggfuzz discovery tests are opt-in:

```sh
go test -tags='integration honggfuzz' ./tests/integration/...
```

## Documentation

- [Quick start](docs/guides/quickstart.md)
- [CLI](docs/reference/cli.md)
- [Configuration](docs/reference/configuration.md)
- [Diagnostics](docs/reference/diagnostics.md)
- [Schemas](docs/reference/schemas.md)
- [Harness synthesis](docs/harness-synthesis.md)
- [Architecture](docs/architecture.md)
- [Compatibility](docs/compatibility.md)
