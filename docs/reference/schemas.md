# JSON schemas

The `schemas/` directory is the public artifact contract. Every JSON file has a
`schema_version`; adding fields is backwards compatible, changing an existing
field's meaning requires a version bump.

| Schema | Artifact |
|---|---|
| `analysis.schema.json` | `.fuzzfw/analysis.json` |
| `ir_facts.schema.json` | `.fuzzfw/ir_facts.json` |
| `plan.schema.json` | `.fuzzfw/plan.json` |
| `harness_plan.schema.json` | `.fuzzfw/generated/<target>/harness_plan.json` |
| `build_manifest.schema.json` | `.fuzzfw/build_manifest.json` |
| `finding.schema.json` | `fuzzfw-out/findings/<id>/finding.json` |
| `summary.schema.json` | `fuzzfw-out/summary.json` |
| `adapter_contract.schema.json` | project adapter contract |
| `baseline.schema.json` | baseline JSON |
| `lock.schema.json` | `.fuzzfw/lock.json` |
| `build_info.schema.json` | `.fuzzfw/build_info.json` and CI `build-info.json` |

Schemas are documentation and validation aids. Runtime code also validates paths,
types, and semantic constraints; schema validation alone is not a security
boundary.
