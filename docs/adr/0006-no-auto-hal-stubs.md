# ADR 0006: no automatic HAL success stubs

- Status: accepted
- Date: 2026-11-15

## Context

Embedded projects call vendor HAL, RTOS, DMA, and MMIO functions. Replacing them
with `NULL` or `return 0` makes builds pass while changing the product's
semantics. The resulting coverage and findings would be misleading.

## Decision

- An external symbol is replaced only by an explicitly registered adapter with a
  reviewed contract, or through a user wrapper.
- Contract validation checks prototype, model, effects, valid context, and
  limitations; mismatches block the target.
- Direct MMIO, inline asm, DMA, ISR, and RTOS paths are blocked in P0.
- A trivial placeholder body is rejected for contracts claiming an input source.
- Every adapter and limitation is recorded in the plan, lock, build-info, and
  summary.

## Consequences

- More targets are `adaptable`/`blocked` at first.
- The supported escape hatch is small and explicit, which keeps original product
  code untouched.
- Adapter review is a customer responsibility; fuzzfw does not claim that a
  contract proves hardware fidelity.
