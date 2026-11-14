# CLI reference

## Global flags

Global flags may appear before or after the command. Values are never passed
through a shell.

| Flag | Meaning |
|---|---|
| `--config PATH` | Configuration file. Default: discover `fuzzfw.toml` upward. |
| `--verbose`, `-v` | Increase log verbosity. Repeat for debug. |
| `--quiet`, `-q` | Suppress non-error human logs. |
| `--log-file PATH` | Also write debug logs to a file. |
| `--version` | Print version and exit 0. |
| `--help`, `-h` | Show help. |

Exit codes: `0` pass, `1` new host-reproduced target finding, `2`
build/environment/self-test failure or incomplete required check, `3` invalid
configuration or usage. The values are a public CI contract.

## `doctor`

```sh
fuzzfw doctor [--json] [--strict]
```

Reports Python-not-required status, platform, Clang target, ASan/UBSan support,
libFuzzer support, external tools, native analyzers, honggfuzz, and engine
availability. `--strict` exits 2 when Clang, sanitizers, or the configured engine
is unavailable.

## `scan`

```sh
fuzzfw scan [PATH] [--compdb PATH] [--artifact-dir PATH] [--json]
```

Imports `compile_commands.json`, records build variants and source hashes,
runs the native or fallback AST/IR analysis, and writes:

- `.fuzzfw/build_manifest.json`
- `.fuzzfw/analysis.json`
- `.fuzzfw/ir_facts.json`
- `.fuzzfw/analyzer-input/` (if used)

`PATH` is the project start directory used for config discovery. `--json` prints
the full analysis object. `scan` exits 2 if no function can be analyzed.

## `plan`

```sh
fuzzfw plan [--target NAME]... [--refresh] [--json]
```

Reads `analysis.json` and produces `.fuzzfw/plan.json`. `--target` accepts a
target name/symbol and may be repeated or comma-separated. `--refresh` re-runs
analysis first. `plan` exits 0 even when targets are `blocked`; inspect the JSON
or use `inspect`.

## `build`

```sh
fuzzfw build [--target NAME]... [--engine NAME] [--refresh] [--json]
```

Generates a typed harness, compiles original translation units and approved
adapters, links a self-test binary, and builds an engine-specific fuzz binary
when the engine is available.

- `--engine` overrides `ci.engine` (`honggfuzz`, `libfuzzer`, `replay`).
- `--refresh` re-runs analysis and planning.
- `--json` prints `.fuzzfw/build_info.json` content.

The command exits 2 unless every selected target reaches `fuzzable` (or
`selftest_passed` when `--engine replay`) and no gate failed.

## `fuzz`

```sh
fuzzfw fuzz [--time BUDGET] [--jobs N] [--engine NAME] [--target NAME]...
                  [--output DIR] [--baseline FILE] [--no-minimize] [--json]
```

Runs an external engine against already built targets, replays corpus, triages
raw artifacts, minimizes reproduced inputs (unless disabled), and writes a
fuzz summary. It does not re-analyze or rebuild. Exit code follows the summary:
1 for a new reproduced target finding, 2 for engine/incomplete failure, 0 for a
clean run.

## `check`

```sh
fuzzfw check [--time BUDGET] [--jobs N] [--engine NAME] [--target NAME]...
                   [--output DIR] [--baseline FILE] [--bootstrap-baseline]
                   [--no-minimize] [--json]
```

Self-contained CI gate:

1. environment/toolchain checks;
2. fresh `scan` (always re-analyzes);
3. plan;
4. build required targets;
5. corpus replay;
6. bounded fuzzing;
7. replay/triage/minimize;
8. baseline comparison;
9. `summary.json`, `junit.xml`, `summary.md`, `diagnostics.json`;
10. stable exit code.

A required target that is blocked, not built, not reached, or not stable makes
the check incomplete (exit 2). A new reproduced target finding exits 1. Harness
or adapter failures exit 2 rather than being promoted to product findings.

`--bootstrap-baseline` approves the findings from this run as the baseline. If no
`--baseline` path is given, it writes `<project>/fuzzfw-baseline.json`.

## `replay`

```sh
fuzzfw replay INPUT_OR_FINDING_DIR [--target NAME] [--attempts N]
                               [--output FILE] [--json]
```

Runs one input in the target's self-test binary in a fresh process. If the input
is a finding directory, the target is read from `finding.json` and `input.bin` is
used. Exit 1 if any attempt reproduces a crash, 0 if not, 2 on infrastructure
failure.

## `report`

```sh
fuzzfw report [--input DIR_OR_SUMMARY] [--format markdown|json|junit]
              [--output FILE]
```

Re-renders a report from `summary.json`. Default format is Markdown; default
input is `fuzzfw-out/`. With no `--output`, writes to stdout.

## `inspect`

```sh
fuzzfw inspect --target NAME [--json]
```

Shows the target's classification, input model, role bindings with evidence,
constraints, context, required translation units, adapters, reasons, and
diagnostics. This is the primary evidence view for FR-30.

## Time budgets

`--time` accepts an integer number of seconds or Go duration syntax (`30s`,
`10m`, `1h`). Budgets are split across built targets; `ci.per_target_seconds`
overrides the split. If the global fuzz budget is exhausted before a target, the
check is marked incomplete.
