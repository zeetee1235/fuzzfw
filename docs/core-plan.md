# Core parser/protocol roadmap

Focus: parsers, protocol handlers, command dispatch, length/overflow bugs, and
state machines. Each item has a deterministic acceptance test and fail-closed
behavior.

## P0 — correctness gaps

### 1. Exact-size input copy / over-read detection — complete

- Copy const fuzz bytes into an exact-size allocation before the target call.
- Empty input gets a one-byte non-null allocation.
- Free after the target/event/teardown sequence.
- `harness.copy_input=false` can opt out for performance, but is not the default.
- Acceptance: `tests/fixtures/c_overread` reads byte 4 from a two-byte input and
  is reported as `address:heap-buffer-overflow` at `R1_HOST_REPRODUCED`.

### 2. C context/session objects — complete

- Explicit opaque/struct context allocation.
- Init/reset/destroy contract; no zeroed object accepted without init.
- Context argument role; per-input reset verification.
- Done: `c_context` fixture passes with explicit init/reset, exact allocation,
  typed pointer, and persistent reset verification. Invalid signatures are
  rejected by the planner.

### 3. Structured length/frame/output roles — complete for explicit contracts

- `OUTPUT_BUFFER` + configured capacity; capacity/`len` relation evidence.
- Multiple-length and length-prefix contract; nested length fields remain
  explicit.
- Integer-overflow guards and optional integer sanitizer profile.
- Done: explicit `OUTPUT_BUFFER`/`CAPACITY` allocation with exact `output_bytes`;
  `c_output` detects a write past the configured capacity.
- Done: length-prefixed frame sequences, per-frame exact copies, and optional
  integer/implicit-conversion/local-bounds profiles.
- Remaining: automatic inner-TLV/nested-length inference is intentionally not
  claimed; use explicit roles or a wrapper.

### 4. Sequence / stateful harness — framed execution and state observation complete

- Length-prefixed frame sequence as one fuzz input.
- Multiple target calls and/or event hooks per sequence.
- State reset/rollback contract; per-frame and whole-sequence reproduction.
- Done: `input = "length_prefixed"` with bounded frames, per-frame exact copy,
  per-frame events, and one setup/context/factory lifecycle.
- Done: optional `state_probe` after each call and `frame_reset` after each frame;
  replay reports record frame count and a deterministic state hash.
- Done: replay/build-info/summary record distinct `previous->current` state
  transitions; per-frame `invariant_check` supplies a semantic oracle.
- Done: corpus deduplication by coverage/state/transition signature.
- Remaining: richer transition graph and state-targeted mutation.

### 5. Command dispatch extraction — constant dictionary complete

- Extract `switch`/enum/command-table constants.
- Command-aware seed and dictionary generation.
- Command-specific target or framing plan where evidence is sufficient.
- Done: switch/compare constants become an engine dictionary; `c_commands`
  discovers command `0x42` from a benign `0x10` seed.
- Done: switch-case commands are extracted as `command_constants` and corpus
  replay reports `commands_covered` as a heuristic coverage metric.
- Done: `command_seeds = true` synthesizes minimal command and command+zero
  seeds, framed for `length_prefixed`; `c_command_seeds` detects its bug with
  replay alone.
- Done: enum case labels produce `command_names`; numeric and name tokens are
  included in the dictionary.
- Done: command seeds honor explicit 1/2/4/8-byte framing, endianness, and
  header-inclusive lengths.
- Done: command dispatch tables are detected by name hint (`command`, `cmd`,
  `dispatch`, `opcode`); numeric IDs and string names are extracted from
  initializer lists and merged into dictionary/seed synthesis.

## P1 — precision

- Interprocedural input taint (caller/callee argument mapping) — complete for
  the deterministic local-call form, including simple local assignment and
  local struct-member aliases. Whole-program points-to and cross-TU alias
  reasoning remain conservative/unknown.
- Return/output invariant oracle — complete in explicit hook form
  (`invariant_check = "symbol"`), with R1 triage and honggfuzz discovery.
- Protocol-aware corpus quality metrics — frame/state coverage recorded per
  corpus input; command-level coverage remains heuristic through the
  dictionary.
- Real firmware pilot — complete for `jsmn` at pinned commit
  `25647e692c7906b96ffd2b05ca54c097948e879c`: replay pass and 4.8M libFuzzer
  executions with no finding; see `docs/pilots.md`.
- Existing unit-test setup/teardown extraction — limited to direct zero-argument
  calls around the target callsite; nested/object construction remains explicit.
- Grammar/state-aware mutation — frame-aware libFuzzer custom mutator for
  `length_prefixed` targets, including configurable TLV framing. honggfuzz
  continues to use its built-in mutator plus the dictionary.
- Optional MSan profile is accepted with an explicit incompatibility check and
  validated end-to-end by `c_msan` and `cpp_msan`
  (`memory:use-of-uninitialized-value` at R1). integer/local-bounds profiles are
  implemented. Complex C++ standard-library code may still require an
  MSan-instrumented libc++ runtime.

## Non-goals

Full RTOS scheduler, real interrupt latency, or a complete DMA engine. Those
require an external emulator/HIL adapter and are not part of the host-lifting
core.
