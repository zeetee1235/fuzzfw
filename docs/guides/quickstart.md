# Quick start

## 1. Requirements

- Linux x86-64
- Go 1.23 or newer
- Clang/LLVM 17 or newer with ASan/UBSan
- CMake and Ninja for projects that use CMake
- Optional: honggfuzz + `hfuzz-clang` for the default P0 engine
- Optional: LLVM/Clang development headers for native analyzers

Check the host:

```sh
fuzzfw doctor
fuzzfw doctor --json
```

## 2. Build fuzzfw

```sh
make build
./fuzzfw --version
```

The Go fallback analysis path needs only Clang. To build the native analyzers:

```sh
# Fedora: dnf install clang-devel llvm-devel
# Debian/Ubuntu: apt install clang libclang-dev llvm-dev
make analyzer
```

If CMake cannot find LLVM, pass explicit paths:

```sh
cmake -S analyzer -B analyzer/build -G Ninja \
  -DLLVM_INCLUDE_DIR=/usr/lib/llvm-18/include \
  -DCLANG_INCLUDE_DIR=/usr/lib/llvm-18/include \
  -DCLANG_CPP_LIBRARY=/usr/lib/llvm-18/lib/libclang-cpp.so \
  -DLLVM_LIBRARY=/usr/lib/llvm-18/lib/libLLVM.so
cmake --build analyzer/build
```

`fuzzfw doctor` reports whether `fuzzfw-analyze` and `fuzzfw-ir-analyze` were
found next to the executable, in `PATH`, or in `analyzer/build/`. The fallback is
explicitly recorded as `AST_JSON_FALLBACK`/textual IR, not silently presented
as native LibTooling.

## 3. Prepare a project

```sh
cmake -S . -B build -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build
```

Create `fuzzfw.toml` at the project root. Start with one target:

```toml
schema_version = 1

[project]
source = "."
compdb = "build/compile_commands.json"

[ci]
engine = "replay"

[[targets]]
name = "parse_packet"
symbol = "parse_packet"
source = "src/parser.c"
header = "include/parser.h"
required = true
max_input_bytes = 4096
seeds = ["tests/fuzzfw/seeds"]
```

`header` must be the real project header that declares the function. `fuzzfw`
does not synthesize a prototype when no declaration can be found.

## 4. Analyze and plan

```sh
fuzzfw scan .
fuzzfw plan --target parse_packet
fuzzfw inspect --target parse_packet
```

Read `plan.json` and `inspect` output before trusting a target:

- `ready_candidate` means static planning passed. It is **not** fuzzable yet.
- `adaptable` means a user wrapper or approved context is required.
- `blocked` means fuzzfw will not build it automatically.

## 5. Build and self-test

```sh
fuzzfw build --target parse_packet --engine replay
```

This emits `.fuzzfw/generated/<target>/harness.c`, compiles the original TU, and
runs isolated smoke cases. The gates are:

1. compile and link;
2. target entry actually hit;
3. input use observed or explicitly weak;
4. repeated executions stable;
5. no crash on benign seeds.

`selftest_passed` is still not `fuzzable`; a fuzz engine binary must also be
built and run.

## 6. Check or fuzz

```sh
# CI-style bounded gate (replay-only is useful for corpus regression).
fuzzfw check --engine replay --time 60s --output fuzzfw-out

# Actual mutation.
fuzzfw check --engine libfuzzer --time 10m --jobs 2 --output fuzzfw-out

# Long local run after building.
fuzzfw fuzz --engine libfuzzer --time 1h --jobs 8
```

Outputs:

```text
fuzzfw-out/
├── summary.json
├── junit.xml
├── summary.md
├── diagnostics.json
├── build-info.json
├── corpus/<target>/
└── findings/<id>/
    ├── input.bin
    ├── finding.json
    ├── sanitizer.log
    ├── replay.sh
    └── repro.json
```

## 7. Baseline policy

The first run with no baseline treats every reproduced finding as new. To
approve the current state explicitly:

```sh
fuzzfw check --engine replay --bootstrap-baseline \
  --baseline fuzzfw-baseline.json --output fuzzfw-out
```

Later runs compare fingerprints against that baseline. Do not silently ignore a
finding without a reviewed baseline update.

## 8. Adapters and wrappers

If a target calls an unapproved hardware symbol, planning blocks it. Add an
adapter with a reviewed contract:

```toml
[[adapters]]
original_symbol = "HAL_UART_Receive"
replacement_source = "tests/fuzzfw/adapters/uart.c"
contract = "tests/fuzzfw/contracts/uart.json"
```

If automatic synthesis is not appropriate, keep the original source untouched
and provide a wrapper:

```c
void fuzzfw_target(const uint8_t *data, size_t size) {
    firmware_test_init();
    app_on_rx(data, size);
    firmware_test_shutdown();
}
```

```toml
[[targets]]
name = "app_on_rx"
symbol = "app_on_rx"
required = true
wrapper_symbol = "fuzzfw_target"
wrapper_source = "tests/fuzzfw/wrappers/app_wrapper.c"
source = "src/app.c"
```

The wrapper ABI is `void wrapper(const uint8_t *, size_t)`. The wrapper source is
compiled as part of the host build but is never treated as an automatic proof of
context validity; build/self-test/replay gates still apply.
