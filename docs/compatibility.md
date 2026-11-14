# Compatibility

## Host and toolchain

| Area | Supported now | Notes |
|---|---|---|
| Host OS | Linux x86-64 | Primary target. Other Linux architectures are not release-validated. |
| Go | 1.23+ | Single static control-plane binary. |
| Clang/LLVM | 17+ | AST JSON fallback and native analyzers target modern Clang. |
| Sanitizers | ASan, UBSan | Default `address,undefined` with `-fno-sanitize-recover=all`. |
| CMake compdb | Yes | `compile_commands.json` with `arguments` or `command`. |
| Make compdb | Yes, if a valid JSON compdb is produced | fuzzfw does not infer link commands from Makefiles. |
| CMake File API | Not yet | P1. |
| Arbitrary host build target | Manual via `build_command`, `link_objects`, `libraries` | No shell interpolation. |

## Languages

| Code | State |
|---|---|
| C11/C17 free/static functions with bytes+length | Implemented. |
| C++17 free functions/namespaces | Implemented. |
| C++ class methods, constructors, RAII, factories | Blocked/adaptable until P1 context planning. |
| `static` function in a non-header TU | Blocked; direct external linkage is impossible without source/build changes. |
| `static inline` in a project header | Supported when a unique header is declared. |
| Variadic functions | Blocked. |
| Direct MMIO, inline asm, DMA, ISR, RTOS scheduler | Blocked in P0. |
| Packed/bitfield layout-sensitive paths | `ABI_LAYOUT`; blocked when target/host triples differ. |

## Input boundaries

| Entry | State |
|---|---|
| `fn(const uint8_t *, size_t)` | Automatic. |
| `fn(uint8_t *, size_t)` | Automatic with a writable copy when read/ownership evidence is sufficient. |
| `fn(const char *, size_t)` | Automatic as bytes+length. |
| `uint16_t`/`uint32_t`/signed length | Automatic with exact-width guards; no silent truncation. |
| Pointer + length + capacity | `adaptable` unless explicit `args` contract; no guessed equality. |
| Output-only buffer | `adaptable`/blocked; wrapper required. |
| Context/object pointer | `adaptable`; wrapper required. |
| UART/network callback | P1 with approved adapter/event model. |
| Existing libFuzzer harness | Not reused in P0; wrapper path available. |

## Engines

| Engine | State |
|---|---|
| `replay` | Implemented and integration-tested; validates build/corpus without mutation. |
| `libfuzzer` | Implemented and integration-tested with Clang. |
| `honggfuzz` | Adapter implemented (`hfuzz-clang`, `-P`, LLVMFuzzerTestOneInput); **release matrix not yet validated**. |
| Persistent target reset | Not yet; isolated execution is the default. |

## ABI and findings

Host ASan/UBSan findings are `HOST_ONLY` unless a device test confirms them. The
tool records target/host triples and warns when they differ. It does not claim
that a host crash is an MCU vulnerability, nor that a non-crashing host path is
safe on the device.

## Explicitly unsupported

Binary-only rehosting, arbitrary MCU emulation, complete RTOS/DMA/ISR scheduling,
automatic object-graph construction, all C++ language constructs, web UI,
central server, and a custom coverage-guided fuzzing engine.
