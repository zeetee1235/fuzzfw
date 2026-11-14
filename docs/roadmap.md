# Roadmap

## Current foundation (M0/M1)

Implemented:

- Go CLI, TOML schema, discovery, stable exit codes.
- Compilation database normalization, variant IDs, build manifest, Git
  provenance.
- Clang AST-JSON fallback, native LibTooling AST analyzer, native LLVM IR fact
  extractor and textual IR fallback.
- Deterministic role inference and C/C++ harness generation for bytes+length.
- Original TU host build with ASan/UBSan, coverage, entry reachability,
  stability, corpus replay, finding reproduction and minimization.
- Adapter contracts, wrapper escape hatch, C++ free functions.
- JSON/JUnit/Markdown reporting, baseline bootstrap.
- libFuzzer integration; honggfuzz adapter implemented but not release-validated.

## M1 completion

- Validate honggfuzz across the supported engine matrix.
- Expand role fixtures: signed/narrow length, output buffer, capacity, ambiguous
  pairs, static header functions.
- Improve diagnostic evidence for every blocked target.
- Add native analyzer contract tests to CI with LLVM development headers.
- Add C++ class factories and limited RAII plans behind explicit user contracts.
- Add existing unit-test setup extraction (P1).
- Add persistent mode only after reset verification.

## M2 host-lifting

- CMake File API target/link metadata.
- Better host library/object binding from project targets.
- Explicit build-overlay support for internal-linkage functions (reviewed,
  non-default).
- HAL profile reuse with versioned contracts.
- ABI layout probes for target/host struct sizes and endianness.
- More precise adapter prototype/effect validation.

## M3 CI hardening

- Parallel target scheduling with per-target budgets.
- Runner sandbox profiles and cgroup integration.
- Signed release artifacts, reproducible builds, pinned toolchain images.
- Node/line normalization improvements for finding fingerprints.
- GitLab/GitHub example repositories with success/failure/incomplete demos.

## M4 ecosystem

- Broader C++17 type/lifetime support.
- Event-driven UART/network input model.
- Optional engine adapters beyond honggfuzz/libFuzzer.
- Customer deployment profiles without a central server.

## Non-goals

Binary-only rehosting, arbitrary MCU emulation, complete RTOS/DMA/ISR
scheduling, automatic object graph synthesis, web UI, cloud dashboard, custom
coverage engine, and LLM-based source modification.
