# Security policy

## Reporting a vulnerability

Do **not** create a public issue for a vulnerability in fuzzfw.

Use the repository's private security advisory feature, or contact the
maintainers through the private channel configured for the distribution. Include:

- affected version/commit;
- host OS/toolchain;
- a minimal reproduction (without customer firmware or secrets);
- expected and actual behavior;
- whether the issue affects the Go control plane, native analyzers, generated
  harness, replay driver, or an external engine integration.

If no private channel is configured yet, open a minimal public issue that says
only "security contact requested" and wait for a maintainer response. Do not
include exploit details.

## Supported versions

Pre-alpha releases are supported on a best-effort basis. A version is
security-supported while it is the latest tagged release or explicitly listed in
release notes.

## Security model

The full model is in [docs/security-model.md](docs/security-model.md). Key
points:

- Target code and `host.build_command` are untrusted native code. fuzzfw does
  not sandbox them.
- Automated runners must use ephemeral/least-privilege environments for untrusted code.
- No telemetry or automatic upload exists; artifacts can still contain secrets.
- Host ASan findings are `HOST_ONLY`, not automatic MCU vulnerability proof.
- The generated harness does not catch target signals or sanitizer reports.

## Dependency and release process

- Dependencies are pinned in `go.mod`/`go.sum`.
- `make lint`, `make test`, and `make test-integration` are the minimum gates.
