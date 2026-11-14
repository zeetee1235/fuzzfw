# Compliance and commercial readiness

This directory is an engineering checklist, **not legal advice**. Before a
commercial release or software copyright registration, have counsel review the
license, contributor policy, contracts, export classification, and customer
data-handling terms.

| Document | Purpose |
|---|---|
| [licensing.md](licensing.md) | Apache-2.0, commercial use, dependencies, dual-licensing considerations |
| [software-registration.md](software-registration.md) | Source/version/authorship evidence for software registration |
| [sbom.md](sbom.md) | SBOM generation and interpretation |
| [release-checklist.md](release-checklist.md) | Release, security, SBOM, checksum, and provenance checks |
| [dependencies.md](dependencies.md) | Dependency/license policy and optional external tools |
| [export-and-trademark.md](export-and-trademark.md) | Export-control and trademark review prompts |

## Current default decisions

- Project license: Apache-2.0.
- Runtime dependencies: Go standard library plus one MIT TOML parser.
- Optional tools: LLVM/Clang, honggfuzz, CMake, Ninja, libFuzzer.
- No telemetry, network upload, or hosted service.
- No vendored fuzzing engine.
- Copyright holder placeholder: fuzzfw contributors. Replace with the actual
  legal entity before registration or commercial distribution.
- Product name `fuzzfw` is a working name; no trademark registration is claimed.

## Company registration pack (recommended)

1. Reserve a legal copyright holder name and year.
2. Update `LICENSE`/`NOTICE`/`AUTHORS.md`/package metadata if needed.
3. Freeze a release tag and produce a source archive.
4. Generate an SBOM, checksums, and signed release notes.
5. Archive the exact source listing required by the registration authority.
6. Keep Git history and contributor sign-offs as authorship evidence.
7. Store customer-specific adapters and findings outside the public source
   archive.
