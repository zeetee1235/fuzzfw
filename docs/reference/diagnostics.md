# Diagnostics reference

Diagnostics are stored in `diagnostics.json`, `plan.json`, `summary.json`, and
JUnit system output. Codes are stable; adding codes is backwards compatible,
changing meaning requires a schema version bump.

## Configuration and input

| Code | Meaning |
|---|---|
| `E_CONFIG_INVALID` | Invalid TOML value, missing required field, duplicate target, bad role count. Exit 3. |
| `E_CONFIG_NOT_FOUND` | Config/source/project path missing. Exit 3. |
| `E_USAGE` | Invalid command usage. Exit 3. |
| `E_TARGET_NOT_FOUND` | Requested target is not in the plan/analysis. |
| `E_TARGET_REQUIRED_NONE` | No required target and no `--target`. |
| `E_COMPDB_MISSING` | Compilation database missing. |
| `E_COMPDB_INVALID` | Invalid JSON/schema, unusable entry, duplicate entry. |
| `E_SOURCE_MISSING` | Source referenced by compdb does not exist. |

## Analysis

| Code | Meaning |
|---|---|
| `E_AST_PARSE` | Clang could not parse a translation unit; original flags and diagnostics are kept. |
| `E_IR_UNAVAILABLE` | IR generation/analysis unavailable or not applicable. |
| `E_IR_MAP_AMBIGUOUS` | AST function could not be joined safely to an IR symbol. |
| `E_ANALYSIS_INCOMPLETE` | Analysis did not complete. |
| `E_ANALYSIS_BUDGET` | Function/IR budget exhausted. |
| `W_NATIVE_ANALYZER_FALLBACK` | Native analyzer failed; Go fallback used. |
| `W_IR_FALLBACK` | AST function had no joined IR fact; textual IR mode is recorded explicitly. |

## Planning and harness

| Code | Meaning |
|---|---|
| `E_HARNESS_ROLE_AMBIGUOUS` | Buffer/length/capacity/output roles conflict or are missing. |
| `E_HARNESS_CONTEXT_UNKNOWN` | Initialization, ownership, or lifetime unknown. |
| `E_HARNESS_SOURCE_MISSING` | No suitable header/wrapper/existing harness. |
| `E_HARNESS_BUILD` | Generated harness or adapter failed to compile. Build log is retained. |
| `E_HARNESS_SMOKE` | Self-test failed; inspect per-case origin. |
| `E_CONTEXT_INVALID` | Verified setup/API contract violated. |
| `E_ENTRY_UNREACHED` | Harness runs but target entry was not hit. |
| `E_INPUT_NOT_OBSERVED` | Reserved for input-use gate failures. |
| `E_STATE_LEAK` | Isolated repetitions differ. |
| `E_DMA_UNMODELED` | DMA transfer/completion/ownership is not modeled. |
| `E_ADAPTER_INVALID` | Adapter contract/prototype/effect mismatch. |
| `E_ADAPTER_TRIVIAL` | Placeholder adapter rejected. |

## Linking and platform

| Code | Meaning |
|---|---|
| `E_LINK_GRAPH_UNKNOWN` | Link inputs or an external symbol graph is incomplete. |
| `E_HAL_UNMODELED` | Hardware external symbol has no approved adapter. |
| `E_MMIO_DIRECT` | Direct MMIO/volatile/int-to-pointer access. P0 blocks. |
| `E_ABI_MISMATCH` | Critical layout/ABI semantics cannot be preserved. |
| `W_ABI_HOST_ONLY` | Target and host triples differ; findings remain `HOST_ONLY`. |

## Execution and CI

| Code | Meaning |
|---|---|
| `E_ENGINE_UNAVAILABLE` | Configured engine/tool unavailable. |
| `E_ENGINE_FAILED` | Engine process failed. |
| `E_TIMEOUT_INFRA` | Global budget or runner failure; check incomplete. |
| `E_REQUIRED_NOT_RUN` | Required target not executed. |
| `E_BASELINE_MISSING` | No baseline; all reproduced findings are new by policy. |
| `E_ARTIFACT_INVALID` | Raw artifact unreadable or inconsistent. |
| `E_INTERNAL` | Unexpected internal failure. Exit 2. |
| `W_CONFIG_UNKNOWN_KEY` | Reserved; current parser rejects unknown keys. |
| `W_INPUT_SENSITIVITY_UNKNOWN` | Input consumption not directly observed. |
| `I_BASELINE_BOOTSTRAPPED` | Baseline written by explicit bootstrap. |
| `I_TARGET_BLOCKED` | Informational blocked target. |
| `W_AUTOCONFIG` | No `fuzzfw.toml`: targets/engine were discovered automatically. |

## Evidence levels

`confidence` is a qualitative evidence level, never a statistical accuracy
number:

- `verified` — established by a successful tool-assisted check;
- `observed` — directly seen in AST/IR/execution;
- `heuristic` — name/type/pattern hint;
- `unknown` — not established.

A hypothesis is not promoted to `verified` because another stage happened to
compile or because coverage increased.
