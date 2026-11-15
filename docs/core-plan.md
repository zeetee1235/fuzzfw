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
- Remaining: state-transition coverage metrics and protocol-semantic oracles.

### 5. Command dispatch extraction — constant dictionary complete

- Extract `switch`/enum/command-table constants.
- Command-aware seed and dictionary generation.
- Command-specific target or framing plan where evidence is sufficient.
- Done: switch/compare constants become an engine dictionary; `c_commands`
  discovers command `0x42` from a benign `0x10` seed.
- Remaining: command names/table extraction, per-command seed synthesis, and
  command-level coverage.

## P1 — precision

- Interprocedural input taint (caller/callee argument mapping) — complete in the
  deterministic local-call form. Expressions that do not map directly to a
  parameter stay unknown.
- Return/output invariant oracle — complete in explicit hook form
  (`invariant_check = "symbol"`), with R1 triage and honggfuzz discovery.
- Protocol-aware corpus quality metrics — frame/state coverage recorded per
  corpus input; command-level coverage remains heuristic through the
  dictionary.
- Grammar/state-aware mutation only after the deterministic harness work.
- Optional MSan profile; integer/local-bounds profiles are implemented.

## Non-goals

Full RTOS scheduler, real interrupt latency, or a complete DMA engine. Those
require an external emulator/HIL adapter and are not part of the host-lifting
core.
