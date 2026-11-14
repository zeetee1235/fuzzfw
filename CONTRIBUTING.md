# Contributing to fuzzfw

Thanks for improving deterministic, honest embedded fuzzing. This project
prefers small, auditable changes over broad automation that hides uncertainty.

## Before you start

- Read `docs/architecture.md`, `docs/harness-synthesis.md`, and
  `docs/security-model.md`.
- For a new target capability, open an issue describing the evidence, expected
  classification, and fail-closed behavior.
- Do not include customer firmware, crash inputs, keys, or proprietary adapter
  code in a public contribution.

## Development setup

```sh
make build
make test
make test-integration
make lint
# optional
make analyzer
```

Requirements: Go 1.23+, Clang/LLVM 17+, CMake, Ninja. Integration tests build
native fixtures.

## Pull requests

- Keep commits focused and signed off under the DCO:
  `git commit -s`.
- Add a deterministic test for every new decision path.
- Add/update a JSON schema when an artifact contract changes.
- Update `docs/reference/diagnostics.md` for new diagnostic codes.
- Do not weaken a gate to make a fixture pass. Fix the fixture or the diagnosis.
- Do not add a shell execution path. Use `internal/proc` with argv arrays.
- Do not add GPL/AGPL runtime dependencies without legal review.

## What maintainers look for

1. Correctness under failure: missing input, missing header, broken link,
   unresolved symbol, timeout, crash.
2. Reproducibility: stable hashes, no timestamps in identities, deterministic
   ordering.
3. Evidence quality: observed vs heuristic vs unknown is explicit.
4. Security: no automatic HAL success stubs, no signal swallowing, no secret
   upload.
5. Small surface area: prefer standard library and existing abstractions.

## Commit sign-off

By signing off, you certify the Developer Certificate of Origin 1.1:

```text
Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off)
    is maintained indefinitely and may be redistributed consistent
    with this project or the open source license(s) involved.
```

## Reporting security issues

Do not open a public issue. Follow [SECURITY.md](SECURITY.md).

## License

Contributions are accepted under Apache-2.0. If the project later introduces a
CLA or dual-license policy, that change must be announced and reviewed before
new contributions are accepted under it.
