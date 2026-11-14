# ADR 0001: Go control plane, C++ analyzers, C runtime

- Status: accepted
- Date: 2026-11-15

## Context

The original specification used Python for orchestration. The product needs
simple enterprise deployment, a single CLI binary, robust subprocess control,
and a native fuzzing path with no interpreter in the loop. Clang/LLVM analysis
must use their native APIs.

## Decision

- Go owns CLI, configuration, build import, planning, harness generation, host
  build orchestration, engine invocation, triage, and reporting.
- C++17 owns Clang LibTooling AST analysis and read-only LLVM IR facts.
- C11 owns the embedded replay driver.
- Processes communicate through versioned JSON files, never cgo or RPC.

## Consequences

- The control plane is easy to distribute and statically linked.
- Native analyzers are optional build artifacts; a Go fallback keeps initial
  adoption simple while explicitly recording reduced evidence.
- There is no Go runtime in the fuzzing loop.
- The team maintains three toolchains and must keep the JSON contract stable.
