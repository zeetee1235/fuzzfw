# Security model

## Trust boundaries

| Boundary | Trust |
|---|---|
| `fuzzfw.toml`, compdb, adapters, wrappers | Project-controlled, reviewed input. |
| Build scripts / `host.build_command` | Executes project code; not sandboxed by fuzzfw. |
| Target/harness/adapters | Untrusted native code executed as the current user unless the runner isolates it. |
| Generated corpus/findings | May contain secrets; treat artifacts as customer data. |
| External engine | Separate process; fuzzfw controls argv but not the engine's internals. |

## Network and data

- No telemetry, account, API key, or automatic upload.
- The analyzer and build path work offline once toolchains are installed.
- The repository does not vendor fuzzing engines.
- Crash inputs and stack traces can contain proprietary strings, keys, or memory
  contents. Choose artifact retention and access controls deliberately.

## Process execution

All subprocesses are launched with argv arrays and `shell=False`. Pipes,
redirections, glob expansion, and shell interpolation are not accepted in
configuration. Child processes run in a new process group and are killed as a
group on timeout. `host.build_command` is still arbitrary project code and must
be reviewed like any build script.

## Runner isolation

Recommended for CI:

- ephemeral container or VM;
- non-privileged user;
- cgroup CPU/memory/PID limits;
- no unnecessary network egress;
- read-only source mount, writable artifact directory only;
- bounded wall-clock and disk usage;
- no secrets in the fuzzing job when running untrusted PR code.

honggfuzz may need `ptrace` and perf permissions depending on mode. Grant the
minimum capability required by the pinned engine configuration; do not default to
`privileged: true`.

ASan reserves a large virtual address space, so `RLIMIT_AS` is not a reliable
memory control. Prefer cgroup memory limits.

## Sanitizer limits

ASan/UBSan on a Linux host catch host-observable memory and undefined behavior.
They do not model MCU memory maps, peripheral side effects, interrupt timing,
DMA completion, or RTOS scheduling. A clean host run does not prove device
safety. A host finding is promoted only to `R1_HOST_REPRODUCED`; `R3_DEVICE_CONFIRMED`
is out of scope.

## Unsafe configurations

The following are blocked or require explicit review:

- automatic `NULL`/`return 0` HAL stubs;
- direct MMIO, inline asm, DMA, ISR, or RTOS scheduler paths;
- automatic object construction from raw bytes;
- silent macros/flags removal to force a build;
- automatic prototype redeclaration when no header exists;
- suppressing target signals or sanitizer reports in the harness;
- `catch (...)` hiding target exceptions in generated wrappers.

## Reporting a vulnerability

Use the project's private maintainer security channel. Do not attach customer
firmware, crash inputs, or proprietary logs to a public issue.
