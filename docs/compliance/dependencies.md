# Dependency policy

## Runtime policy

- Prefer the Go standard library.
- A new runtime dependency needs a license, maintenance, security, and SBOM
  review.
- No GPL/AGPL runtime dependency without an explicit company/legal decision.
- Do not vendor a fuzzing engine into the control plane.
- C/C++ analyzers may link LLVM/Clang shared libraries; they must remain separate
  processes from the Go binary.

## Current Go dependencies

| Module | Version | License | Purpose |
|---|---|---|---|
| `github.com/pelletier/go-toml/v2` | `v2.4.3` | MIT | TOML decoding with strict unknown-key checks |

The version is pinned in `go.mod`/`go.sum`. Update via a reviewed pull request
and regenerate the SBOM.

## Optional external tools

| Tool | License | Distribution relationship |
|---|---|---|
| Clang/LLVM | Apache-2.0 WITH LLVM-exception | Compiler and optional analyzer libraries |
| libFuzzer | Apache-2.0 WITH LLVM-exception | Linked into fuzz binary via `-fsanitize=fuzzer` |
| honggfuzz | Apache-2.0 | Separate executable/wrapper |
| CMake | BSD-3-Clause | Build tool |
| Ninja | Apache-2.0 | Build tool |

These tools are not vendored. A release image that installs them must carry
their notices and version information separately.

## Customer adapters

Customer adapter source and contracts are customer-controlled. They must not be
committed to the public fuzzfw repository. Their licenses do not change fuzzfw's
license; distribution terms are a customer/company matter.

## Adding a dependency

1. Explain why the standard library is insufficient.
2. Check license compatibility and notice obligations.
3. Check maintenance/security posture and transitive graph.
4. Pin the version and update `go.sum`.
5. Add it to the SBOM and this document.
6. Add a test that exercises the integration boundary.
