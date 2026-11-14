# ADR 0004: native analyzers are optional processes

- Status: accepted
- Date: 2026-11-15

## Context

Clang LibTooling gives richer declarations, USRs, and C++ context than the JSON
AST dump. LLVM IR gives compiled memory/argument facts. However, LLVM
development headers are not installed on every CI image, and some customers use
vendored/cross toolchains.

## Decision

- Ship native `fuzzfw-analyze` and `fuzzfw-ir-analyze` as separate executables.
- Invoke them with JSON input/output; never link Clang/LLVM into the Go binary.
- If absent or failed, fall back to Clang AST JSON/textual LLVM IR and record
  `AST_JSON_FALLBACK`/`textual_llvm_ir` and `W_NATIVE_ANALYZER_FALLBACK`.
- Never present fallback evidence as native LibTooling evidence.

## Consequences

- Users without LLVM dev headers can still start.
- Release validation must test both native and fallback modes.
- The JSON contract is the compatibility boundary.
