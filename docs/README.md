# Documentation

| Document | Purpose |
|---|---|
| [Quick start](guides/quickstart.md) | First successful run |
| [Architecture](architecture.md) | Go/C++/C boundaries and data flow |
| [Harness synthesis](harness-synthesis.md) | Role inference and validation gates |
| [Security model](security-model.md) | Trust boundaries and runner isolation |
| [Compatibility](compatibility.md) | Supported code/build/engine matrix |
| [CLI](reference/cli.md) | Commands, flags, exit codes |
| [Configuration](reference/configuration.md) | `fuzzfw.toml` fields |
| [Diagnostics](reference/diagnostics.md) | Diagnostic codes and evidence levels |
| [Schemas](reference/schemas.md) | Artifact JSON contracts |

The original implementation specification is at
[`../fuzzfw_implementation_spec_v0.2.md`](../fuzzfw_implementation_spec_v0.2.md).
The control plane is Go; the spec's Python module table is historical.
