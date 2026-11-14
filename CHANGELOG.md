# Changelog

All notable changes to this project are documented here. The format follows
Keep a Changelog and the project uses semantic versioning once it reaches 1.0.

## [Unreleased]

### Added

- Go control plane with `doctor`, `scan`, `plan`, `build`, `fuzz`, `check`,
  `replay`, `report`, and `inspect`.
- Strict TOML configuration, compilation database import, build variants,
  source/build manifests, and Git provenance.
- Native Clang LibTooling AST analyzer and read-only LLVM IR fact extractor,
  with explicit Go fallbacks.
- Deterministic bytes+length role inference and C/C++ harness generation.
- Original translation unit host build with ASan/UBSan, sanitizer coverage,
  entry reachability, input-use evidence, stability, and corpus replay.
- Approved HAL adapter contracts and user wrapper escape hatch.
- libFuzzer and honggfuzz engine adapters; libFuzzer integration-tested.
- Replay, finding classification, delta minimization, baseline bootstrap, JSON,
  JUnit, and Markdown reports.
- C, HAL, and C++17 fixtures; unit and tagged integration tests.
- Apache-2.0 license, SBOM generator, SPDX header check, compliance and
  software-registration checklists, ADRs, and release workflow scaffolding.

### Known limitations

- honggfuzz adapter is not yet validated across the release matrix.
- C++ methods/object lifetime, DMA/ISR/RTOS models, persistent mode, New PM
  precision analyses, and unit-test context extraction are future work.
- Host findings are `HOST_ONLY`; device confirmation is out of scope.
