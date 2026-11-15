# Configuration reference

`fuzzfw.toml` is TOML, schema version 1. Unknown keys are rejected so typos fail
closed. Paths are resolved relative to the project root unless stated otherwise.

## Top level

```toml
schema_version = 1
```

| Key | Default | Meaning |
|---|---|---|
| `schema_version` | `1` | Required schema version. A different value is a configuration error. |

## `[project]`

| Key | Default | Meaning |
|---|---|---|
| `name` | directory name | Project label in artifacts. |
| `source` | `"."` | Source root. Relative to the config file directory. |
| `compdb` | `build/compile_commands.json` | Compilation database. Relative to `source`. |
| `artifact_dir` | `.fuzzfw` | Local analysis/build state. Relative to `source`. |
| `source_revision` | `auto` | `auto` reads Git HEAD and a bounded dirty digest; any other string is stored verbatim. |

## `[host]`

| Key | Default | Meaning |
|---|---|---|
| `triple` | `x86_64-unknown-linux-gnu` | Expected host triple (recorded for ABI review). |
| `clang` | `clang` | C compiler executable or path. |
| `clangxx` | `clang++` | C++ compiler executable or path. |
| `build_command` | unset | **argv array**, not a shell string. Run before target compilation for project-specific host libraries. |
| `link_libraries` | `[]` | Library names; `m` becomes `-lm`. |
| `link_objects` | `[]` | Object paths relative to project root. |
| `libraries` | `[]` | Library file paths relative to project root. |
| `extra_cflags` | `[]` | Extra host compiler flags. |
| `extra_ldflags` | `[]` | Extra host linker flags. |
| `sanitizers` | `["address","undefined"]` | Supported: address, undefined, leak, memory, thread, integer, implicit-conversion, local-bounds, pointer-overflow, object-size. `memory` (MSan) cannot be combined with address/thread; MSan also requires an MSan-instrumented C++ runtime. Integer/implicit profiles are opt-in because they can be noisy on intentional wrapping. |
| `optimization` | `-O1` | `-O0`..`-O3`, `-Os`, `-Oz`. |
| `coverage` | `true` | Adds `-fsanitize-coverage=trace-pc-guard` for self-test. |
| `coverage_mode` | `trace-pc-guard` | `trace-pc-guard` or `none`. |
| `timeout_seconds` | `300` | Per compiler/linker/self-test process timeout. |

Target-specific flags (`-mthumb`, `-mcpu`, `-mfpu`, `-mfloat-abi`, cross
sysroots, `-nostdlib`, `-Werror`, LTO, ABI-changing `-fshort-enums`/packed flags)
are removed for the host build and recorded in the build delta. Preprocessor
definitions, include paths, forced includes, and standards are preserved.

## `[analysis]`

| Key | Default | Meaning |
|---|---|---|
| `timeout_seconds` | `300` | Per analyzer/IR invocation. |
| `extra_args` | `[]` | Extra Clang analysis flags. |
| `emit_ir` | `true` | Generate and analyze textual LLVM IR. |
| `ir_opt_level` | `-O0` | IR analysis optimization level. |
| `ast_only` | `false` | Skip IR; forces AST-only evidence. |
| `max_functions` | `5000` | Analysis budget; exceeding it reports incomplete analysis. |
| `max_ir_bytes` | `67108864` | Maximum accepted IR text size. |
| `analyzer` | auto | Native `fuzzfw-analyze` path/name. |
| `ir_analyzer` | auto | Native `fuzzfw-ir-analyze` path/name. |

## `[harness]`

| Key | Default | Meaning |
|---|---|---|
| `max_input_bytes` | `4096` | Global maximum passed to engines and harness guards. |
| `reproduction_attempts` | `3` | Isolated replay attempts per finding. |
| `minimize` | `true` | Delta-debug reproduced inputs. |
| `min_input_bytes` | `0` | Minimum size retained by minimization. |
| `preserve_nonnull_on_empty` | `true` | Mutable buffers allocate one byte when input size is zero. |
| `persistent_reset_check` | `true` | Repeat the same input inside one process and require identical coverage before persistent execution is allowed. |
| `copy_input` | `true` | Copy engine bytes into an exact-size sanitizer-visible allocation before the target call; required to catch reads past `size`. |

## `[ci]`

| Key | Default | Meaning |
|---|---|---|
| `mode` | `pr` | `pr`, `nightly`, or `release` (reported policy hint). |
| `engine` | `honggfuzz` | `honggfuzz`, `libfuzzer`, or `replay`. |
| `time_seconds` | `600` | Default fuzz budget. |
| `jobs` | `2` | Engine workers. |
| `fail_on_new_reproduced` | `true` | A new R1 target finding exits 1. |
| `incomplete_is_failure` | `true` | Missing required checks exit 2. |
| `baseline` | unset | Finding fingerprint baseline path. |
| `corpus_dir` | unset | Additional seed corpus copied into the output corpus. |
| `output_dir` | `fuzzfw-out` | Default output directory. |
| `max_findings` | `50` | Reserved artifact cap. |
| `per_target_seconds` | unset | Per-target override for the total split. |

## `[[targets]]`

| Key | Default | Meaning |
|---|---|---|
| `name` | required | Unique target label. |
| `symbol` | `name` | Function name or C++ qualified name. |
| `source` | auto | TU/source path. Used for matching and wrapper builds. |
| `header` | auto | Header that declares the function. No automatic prototype synthesis. |
| `required` | `false` | Required for `check`; at least one required target or `--target` is mandatory. |
| `input` | auto | `bytes_length`, `length_prefixed`, `manual_wrapper`, or `existing_harness`. `length_prefixed` reads a 4-byte little-endian frame length before each call. |
| `max_input_bytes` | harness default | Per-target cap; must not exceed the global cap (0 inherits). |
| `output_bytes` | unset | Allocated output capacity for explicit `OUTPUT_BUFFER`/`CAPACITY` roles. |
| `max_frames` | `64` for `length_prefixed` | Maximum frames processed from one fuzz input. |
| `state_probe` | unset | `int(void)` or `int(context *)` function called after each target/event sequence; its value is folded into the state hash. |
| `frame_reset` | unset | `void(void)` or `void(context *)` function called after each frame in `length_prefixed` mode; requires `input = "length_prefixed"`. |
| `invariant_check` | unset | Post-call oracle: `int(int)` or `int(int, const uint8_t *, size_t)`. Non-zero aborts as a triaged `target_invariant` finding. Requires a non-void integer target return and cannot be used with `manual_wrapper`. |
| `command_seeds` | `false` | Synthesize minimal corpus seeds from `command_constants` (command only, command + zero). For `length_prefixed`, each is wrapped in a valid frame. |
| `setup` | unset | Explicit setup function called before the target. Must be declared by the included header. |
| `teardown` | unset | Explicit teardown function called after the target. |
| `factory` | unset | Explicit C++ factory symbol for a member function target. Value, reference, raw pointer, `std::unique_ptr`, and `std::shared_ptr` returns are recognized. |
| `factory_lifetime` | unset | Must be `external` for a reference-returning factory; no automatic destruction is emitted. |
| `destroy` | unset | Required when `factory` returns a raw pointer; must take the object pointer. |
| `wrapper_symbol` | unset | User wrapper entry symbol; must be set with `wrapper_source`. |
| `wrapper_source` | unset | User wrapper source compiled into the host build. |
| `seeds` | `[]` | Seed files or directories. |
| `args` | unset | Explicit role list, one per parameter: `FUZZ_BYTES`, `FUZZ_BYTES_MUTABLE`, `LOGICAL_LENGTH`, `CAPACITY`, `OUTPUT_BUFFER`, `CONTEXT`, `CONFIG`, `UNKNOWN`. `OUTPUT_BUFFER` requires `output_bytes`; `CONTEXT` requires `targets.context`; `CONFIG` still requires a wrapper. |
| `build_variant` | unset | Select an exact compilation-database variant. |

For a C++ member function, use an explicit factory instead of raw memory:

```toml
[[targets]]
name = "parser_feed"
symbol = "Parser::feed"
header = "include/parser.hpp"
factory = "Parser::create_default"
required = true

# Raw pointer factory:
# factory = "RawParser::create"
# destroy = "RawParser::destroy"
```

The factory must be declared in the included header and return the target
class by value, pointer + `destroy`, `std::unique_ptr`, or `std::shared_ptr`.
No constructor is guessed and no zeroed object is treated as one.

The wrapper ABI is:

```c
void wrapper(const uint8_t *data, size_t size);
```

If the target needs a writable buffer, the wrapper owns the copy. If a target
needs a context or output buffer, a wrapper is the supported P0 escape hatch.

### `[targets.context]`

For C APIs that take a context pointer:

```toml
[targets.context]
kind = "opaque"       # currently opaque
size = 16             # exact allocation size in bytes
init = "parser_context_init"
reset = "parser_context_reset"
destroy = "parser_context_destroy" # optional
arg = 0               # context parameter index
```

`init` must be `int(void *)` or `void(void *)`; `reset` and `destroy` must be
`void(void *)`. The harness allocates zeroed memory, calls init, passes the
typed pointer to the target, calls reset/destroy, and frees it. No zeroed
object is accepted without an explicit init.

## `[[adapters]]`

| Key | Meaning |
|---|---|
| `original_symbol` | External symbol being replaced. |
| `replacement_source` | Reviewed C/C++ source that defines the symbol. |
| `contract` | Adapter contract JSON path. |

Adapter contract:

```json
{
  "schema_version": 1,
  "original_symbol": "HAL_UART_Receive",
  "prototype": "int(void *, uint8_t *, size_t, uint32_t)",
  "model": "input_source",
  "effects": ["write_buffer", "return_status"],
  "max_write": "min(requested_len, available_input)",
  "valid_context": "uart_handle_initialized",
  "nondeterminism": "none",
  "limitations": ["no_real_interrupt_timing", "no_dma"]
}
```

The contract prototype is checked against the project declaration when one is
available. Unrecognized models/effects/contexts/event models fail planning.
Event contracts may additionally declare:

| Contract key | Meaning |
|---|---|
| `event_model` | `none`, `uart_rx`, `dma_completion`, `isr_callback`, or `rtos_event`. |
| `completion` | `synchronous` or `deferred`. Deferred DMA requires an explicit event hook. |
| `ownership` | `caller`, `adapter`, or `shared`; DMA buffer ownership must be explicit. |

Adapters can consume the fuzz input stream through `fuzzfw_events.h`:

```c
size_t fuzzfw_input_read(void *dst, size_t requested);
size_t fuzzfw_input_remaining(void);
const uint8_t *fuzzfw_input_peek(size_t *available);
```

Target event hooks are declared in the included header with `void hook(void)`.
They run before or after the target call; the input stream is reset for every
process/iteration by the generated harness. The Adapter does
not make a target fuzzable until build and self-test gates pass.

## Complete example

```toml
schema_version = 1

[project]
name = "sensor-firmware"
source = "."
compdb = "build/compile_commands.json"
source_revision = "auto"

[host]
clang = "clang"
clangxx = "clang++"
sanitizers = ["address", "undefined"]
optimization = "-O1"

[analysis]
emit_ir = true

[harness]
max_input_bytes = 4096
reproduction_attempts = 3

[ci]
engine = "honggfuzz"
time_seconds = 600
jobs = 2
baseline = "fuzzfw-baseline.json"

[[targets]]
name = "sensor_decode"
symbol = "sensor_decode"
source = "src/sensor.c"
header = "include/sensor.h"
required = true
max_input_bytes = 4096
seeds = ["tests/fuzzfw/seeds"]

[[targets.events]]
symbol = "dma_event_flush"
phase = "before"       # before or after the target call

[[adapters]]
original_symbol = "HAL_UART_Receive"
replacement_source = "tests/fuzzfw/adapters/uart.c"
contract = "tests/fuzzfw/contracts/uart.json"
```
