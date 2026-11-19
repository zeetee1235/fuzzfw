# fuzzfw

Deterministic source-level host-lifting for embedded C/C++ fuzzing.

`fuzzfw` analyzes the C/C++ that actually compiles, replaces only approved
hardware boundaries, relinks the original translation units on Linux, verifies
that the target is reached and consumes input, and turns reproduced crashes into
replayable artifacts.

> Status: pre-alpha. Linux x86-64. libFuzzer and honggfuzz supported;
> honggfuzz is optional.

## Requirements

For the **release binary**:

- Linux x86-64 (static Go binary; no glibc version requirement)
- Clang with ASan/UBSan support
- CMake
- `make` or `ninja` for CMake projects

For **building from source**:

- Go 1.23+
- Git
- The release requirements above
- Optional: LLVM/Clang development headers for native analyzers

`honggfuzz` is optional. Without it, zero-config and normal `check` runs use
libFuzzer.

## Supported distributions

Tested by extracting the release archive and running the bundled example with
the commands below. Every case starts real libFuzzer mutation and ends with the
same `parse_packet` heap-buffer-overflow.

| Distribution | Tested image | Install command |
|---|---|---|
| Ubuntu 22.04 / 24.04 | `ubuntu:22.04`, `ubuntu:24.04` | `sudo apt-get update && sudo apt-get install -y clang cmake make` |
| Fedora | `fedora:latest` (44) | `sudo dnf install -y clang cmake make` |
| CentOS Stream 9 | `quay.io/centos/centos:stream9` | `sudo dnf install -y clang cmake make` |
| RHEL 8 / 9 | `ubi8/ubi`, `ubi9/ubi` | `sudo dnf install -y clang cmake make` |

`ninja` is optional. If it is installed, zero-config uses Ninja; otherwise CMake
uses Make. On CentOS Stream 9, `ninja-build` requires the CRB repository.

Ubuntu 22.04 ships Clang 14 and was verified with the bundled example. Clang 17+
is recommended for the full feature set.

## Install a release

```sh
tar xzf fuzzfw-0.0.2-linux-amd64.tar.gz
cd fuzzfw-0.0.2-linux-amd64
./fuzzfw doctor
cd examples/simple-parser
./run.sh
```

Expected: exit `1`, one host-reproduced `address:heap-buffer-overflow` in
`parse_packet`. The archive contains the binary, documentation, and the
zero-config example. No `fuzzfw.toml`, Go toolchain, or manual build step is
needed.

The example first run auto-configures and builds CMake, discovers
`parse_header` and `parse_packet`, attaches `seeds/`, and starts libFuzzer. The
crash input is produced by mutation, not copied from `corpus/`.

## From source

```sh
make build
./fuzzfw doctor
```

One-shot source verification (installs dependencies with apt, dnf/yum, pacman,
zypper, or apk; builds; runs every example with expected exit codes):

```sh
./scripts/quickstart.sh
./scripts/quickstart.sh --no-install        # dependencies already installed
./scripts/quickstart.sh --skip-integration  # skip the ~1 minute test suite
./scripts/quickstart.sh --skip-analyzer     # use the Go fallback analyzer
```

The script and `tests/fixtures/` exist only in the source repository. They are
not included in the binary release archive.

Optional native analyzers (builds `fuzzfw-analyze` and `fuzzfw-ir-analyze`):

```sh
make analyzer   # requires clang-devel and llvm-devel
```

Without them, fuzzfw records the Go AST-JSON/textual-IR fallback.

## Commands

| Command | Purpose |
|---|---|
| `doctor` | Check Clang, sanitizers, analyzers, and engines. |
| `scan` | Import the compilation database and analyze functions. |
| `plan` | Produce a deterministic host-lift plan with evidence. |
| `build` | Generate a harness, compile original TUs, and self-test. |
| `fuzz` | Run a built target in an external engine and triage findings. |
| `check` | Zero-config or configured analyze/build/replay/fuzz gate. |
| `replay` | Re-run one finding input in a fresh process. |
| `report` | Re-render Markdown, JSON, or JUnit output. |
| `inspect` | Show roles, constraints, adapters, and diagnostics. |

Exit codes: `0` pass, `1` new host-reproduced finding, `2`
build/environment/self-test failure, `3` invalid configuration or usage.

## Zero-config check

Run `fuzzfw check` in a project without `fuzzfw.toml`:

```sh
cd examples/simple-parser
./run.sh
# or: ../../fuzzfw check --time 30s
```

fuzzfw auto-configures CMake when `compile_commands.json` is missing, treats
ready candidates as required targets, attaches `seeds/`,
`tests/fuzzfw/seeds/`, or `corpus/`, and prefers libFuzzer, then honggfuzz, then
replay. Auto mode uses a 20-second budget unless `--time` is given. Every
automatic decision is recorded as `W_AUTOCONFIG`.

To customize targets or the engine, add `fuzzfw.toml`:

```toml
schema_version = 1

[project]
source = "."
compdb = "build/compile_commands.json"

[ci]
engine = "libfuzzer"
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
seeds = ["seeds"]
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

## Source fixtures

These commands require the source repository because `tests/fixtures/` is not
shipped in the binary archive.

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

Replay a finding in a fresh process:

```sh
../../../fuzzfw replay --attempts 3 fuzzfw-out/findings/<id>
```

Run mutation instead of corpus replay:

```sh
../../../fuzzfw check --engine libfuzzer --time 10s --output fuzzfw-out
```

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

honggfuzz discovery tests are opt-in:

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
