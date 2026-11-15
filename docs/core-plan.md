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

### 2. C context/session objects — next

- Explicit opaque/struct context allocation.
- Init/reset/destroy contract; no zeroed object accepted without init.
- Context argument role; per-input reset verification.
- Acceptance: parser with `ParserContext *` builds and finds a test bug without a
  user wrapper; invalid init/reset is blocked.

### 3. Structured length/frame/output roles

- `OUTPUT_BUFFER` + configured capacity; capacity/`len` relation evidence.
- Multiple-length and length-prefix contract; nested length fields remain
  explicit.
- Integer-overflow guards and optional integer sanitizer profile.
- Acceptance: TLV-style fixture with header length vs remaining data; output
  buffer write-overrun fixture.

### 4. Sequence / stateful harness

- Length-prefixed frame sequence as one fuzz input.
- Multiple target calls and/or event hooks per sequence.
- State reset/rollback contract; per-frame and whole-sequence reproduction.
- Acceptance: protocol state fixture reaches a later state only with a valid
  sequence; invalid reset reports `E_STATE_LEAK`/`E_CONTEXT_INVALID`.

### 5. Command dispatch extraction

- Extract `switch`/enum/command-table constants.
- Command-aware seed and dictionary generation.
- Command-specific target or framing plan where evidence is sufficient.
- Acceptance: command handler fixture discovers a non-first command bug from an
  empty corpus.

## P1 — precision

- Interprocedural input taint (caller/callee argument mapping).
- Return/output invariant oracle.
- Protocol-aware corpus quality metrics (valid frames, command/state coverage).
- Grammar/state-aware mutation only after the deterministic harness work.
- Optional MSan/integer/local-bounds profiles.

## Non-goals

Full RTOS scheduler, real interrupt latency, or a complete DMA engine. Those
require an external emulator/HIL adapter and are not part of the host-lifting
core.
