# Compatibility

## Host and toolchain

| Area | Supported now | Notes |
|---|---|---|
| Host OS | Linux x86-64 | Primary target. Other Linux architectures are not release-validated. |
| Go | 1.23+ | Single static control-plane binary. |
| Clang/LLVM | 17+ | AST JSON fallback and native analyzers target modern Clang. |
| Sanitizers | ASan, UBSan, LSan, MSan, TSan, integer, implicit-conversion, local-bounds, pointer-overflow, object-size | Default `address,undefined` with `-fno-sanitize-recover=all`. MSan requires an instrumented runtime and cannot be combined with ASan/TSan. |
| CMake compdb | Yes | `compile_commands.json` with `arguments` or `command`. |
| Make compdb | Yes, if a valid JSON compdb is produced | fuzzfw does not infer link commands from Makefiles. |
| CMake File API | Not yet | P1. |
| Arbitrary host build target | Manual via `build_command`, `link_objects`, `libraries` | No shell interpolation. |

## Languages

| Code | State |
|---|---|
| C11/C17 free/static functions with bytes+length | Implemented. |
| C++17 free functions/namespaces | Implemented. |
| C++ class methods with explicit factory | Supported for value, raw pointer + destroy, `unique_ptr`, and `shared_ptr` returns. |
| C++ constructors / arbitrary object graphs | Blocked; explicit factory or wrapper required. |
| C++ reference-returning factory | Supported only with `factory_lifetime = "external"`; no automatic destruction. |
| C++ static member functions | Supported directly without a factory. |
| `static` function in a non-header TU | Blocked; direct external linkage is impossible without source/build changes. |
| `static inline` in a project header | Supported when a unique header is declared. |
| Variadic functions | Blocked. |
| Direct MMIO, inline asm | Blocked. |
| DMA / ISR / RTOS scheduler | Explicit adapter event model + event hooks only; no real scheduling. |
| Packed/bitfield layout-sensitive paths | `ABI_LAYOUT`; blocked when target/host triples differ. |

## Input boundaries

| Entry | State |
|---|---|
| `fn(const uint8_t *, size_t)` | Automatic. |
| `fn(uint8_t *, size_t)` | Automatic with a writable copy when read/ownership evidence is sufficient. |
| `fn(const char *, size_t)` | Automatic as bytes+length. |
| `uint16_t`/`uint32_t`/signed length | Automatic with exact-width guards; no silent truncation. |
| Pointer + length + capacity | Explicit `args` contract with `output_bytes`; no guessed equality. |
| Output-only buffer | Explicit `OUTPUT_BUFFER`/`CAPACITY` roles; otherwise blocked. |
| Context/object pointer | C context lifecycle via `[targets.context]`; C++ object pointer via factory. |
| Stateful frames | `input = "length_prefixed"` with `state_probe` and `frame_reset`. |
| Post-call invariant | Explicit `invariant_check` hook (`int(int)` or return+output form). |
| UART/network callback | P1 with approved adapter/event model; not implemented yet. |
| Existing libFuzzer harness | Not reused in P0; wrapper path available. |

## Engines

| Engine | State |
|---|---|
| `replay` | Implemented and integration-tested; validates build/corpus without mutation. |
| `libfuzzer` | Implemented and integration-tested with Clang. |
| `honggfuzz` | Validated with upstream `hfuzz-clang`/`libhfuzz` persistent mode; wider version matrix still pending. |
| Persistent target reset | Same-process coverage reset probe is mandatory by default; a leak reports `E_STATE_LEAK`. |

## ABI and findings

Host ASan/UBSan findings are `HOST_ONLY` unless a device test confirms them. The
tool records target/host triples and warns when they differ. It does not claim
that a host crash is an MCU vulnerability, nor that a non-crashing host path is
safe on the device.

## Explicitly unsupported

Binary-only rehosting, arbitrary MCU emulation, complete RTOS/DMA/ISR scheduling,
automatic object-graph construction, all C++ language constructs, web UI,
central server, and a custom coverage-guided fuzzing engine.
