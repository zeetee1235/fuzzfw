# Architecture

## Design goal

Keep the product's original C/C++ translation units intact, make the hardware
boundary explicit, verify the host target actually reaches and consumes the
fuzzed input, and produce artifacts that a CI runner can trust without a
central service.

## Process boundaries

```text
┌──────────────────────────── fuzzfw (Go) ────────────────────────────┐
│ config → compdb → analyzer invocation → planner → harness → build  │
│       → engine → replay/triage → JSON/JUnit/Markdown               │
└───────┬──────────────────┬───────────────────┬─────────────────────┘
        │ JSON file        │ argv + JSON       │ argv
        ▼                  ▼                   ▼
  fuzzfw-analyze      fuzzfw-ir-analyze    clang / clang++
  Clang LibTooling    LLVM IR walker       host build
        │                  │                   │
        └────────── analysis.json / ir_facts.json ──────────┐
                                                           ▼
                                              native self-test + fuzz binary
                                                           │
                                              honggfuzz / libFuzzer
```

- The Go binary is the only orchestration layer. It does not link Clang or
  LLVM, so the control plane remains a small static binary.
- Native analyzers are separate processes. They are optional; the Go fallback
  uses `clang -Xclang -ast-dump=json` and textual LLVM IR when they are absent.
- The generated harness and original source objects are compiled by Clang into
  opaque native executables. The fuzzing loop has no Go or Python runtime.
- External engines are invoked with argv arrays. No shell, pipes, or
  redirections are allowed.

## Data flow

```text
compile_commands.json
   │ build_import
   ▼
build_manifest.json ──► analyzer<C++/Go> ──► analysis.json
                                      └────► ir_facts.json
   │
   ▼
plan.json ──► harness_plan.json ──► generated/harness.c[.cpp]
   │                                      │
   │                                      ▼
   └────────────► host_build ──► selftest binary + fuzz binary + build_info.json
                                      │
                                      ▼
                              engine raw artifacts
                                      │
                              replay/triage
                                      ▼
                         findings/<id>/finding.json
                                      │
                                      ▼
                         summary.json + junit.xml + report
```

## Determinism

- `analysis.json`, `plan.json`, and `harness_plan.json` are serialized with
  sorted keys and stable ordering.
- Plan IDs and harness IDs are SHA-256 hashes of canonical JSON. Timestamps are
  not part of those identities.
- Source paths in fingerprints are project-relative. Generated outputs under
  `.fuzzfw/` and `fuzzfw-out/` are excluded from Git dirty-state provenance.
- Harness source contains no timestamps or random identifiers. The same typed
  plan emits the same bytes on the same generator version.
- Build objects are content-addressed by source path, selected flags, and
  profile.

## Fail-closed decisions

| Observation | Result |
|---|---|
| No compile database | `E_COMPDB_MISSING`, exit 3 |
| Clang cannot parse original TU | `E_AST_PARSE`; target remains blocked/adaptable |
| Ambiguous buffer/length roles | `adaptable`, no harness |
| No unique header declaration | `blocked`, no prototype re-declaration |
| Unapproved HAL symbol | `blocked`, `E_HAL_UNMODELED` |
| Direct MMIO / inline asm / DMA / RTOS | `blocked` |
| Harness compiles but target not reached | `E_ENTRY_UNREACHED` |
| Repeated isolated runs differ | `E_STATE_LEAK` |
| Required target not executed | exit 2 |
| New reproduced target crash | exit 1 |
| Harness/adapter crash reproduced | exit 2, not a product finding |

## Module map

| Spec module | Implementation |
|---|---|
| `fuzzfw` CLI | `cmd/fuzzfw`, `internal/cli` |
| `build_import` | `internal/compdb`, `internal/manifest` |
| `analyze` | `analyzer/clang`, fallback `internal/analyzer` |
| `ir_analyze` | `analyzer/llvm` (LoopInfo/DominatorTree, AA/MemorySSA, compare constants), fallback `internal/analyzer/ir.go` |
| `plan` | `internal/planner` |
| `harness` | `internal/harness` |
| `host_build` | `internal/hostbuild` |
| `runtime` | `runtime/replay`, generated C harness |
| `engine/honggfuzz` | `internal/engine` |
| `triage` | `internal/triage` |
| `report` | `internal/report` |

## Deliberate non-goals

No web UI, central database, custom fuzzing engine, automatic object graph
construction, binary-only rehosting, or LLM code modification. The project
should stay a deterministic local/CI tool that composes existing compilers and
fuzzers.
