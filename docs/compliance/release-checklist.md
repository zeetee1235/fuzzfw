# Release checklist

## Code and contracts

- [ ] `CHANGELOG.md` and version metadata updated.
- [ ] JSON schema changes reviewed; versions bumped for semantic changes.
- [ ] Diagnostic code table updated.
- [ ] No target body copying, automatic HAL stubs, or shell execution added.
- [ ] New parser/fuzzer paths have fail-closed tests.
- [ ] Fixtures with intentional bugs are clearly marked and excluded from
      production seed sets.

## Verification

- [ ] `make lint`
- [ ] `make test`
- [ ] `make test-integration`
- [ ] Native analyzers built and tested on the supported LLVM matrix.
- [ ] Fallback analyzer tested without native tools.
- [ ] Clean fixture exits 0; crash fixture exits 1; blocked/incomplete exits 2.
- [ ] Baseline bootstrap and baseline comparison tested.
- [ ] libFuzzer integration tested; honggfuzz status recorded honestly.
- [ ] `fuzzfw doctor` output reviewed.

## Security and operations

- [ ] No secrets or customer firmware in the repository/artifacts.
- [ ] Unsafe runner assumptions documented.
- [ ] Dependency licenses and notices reviewed.
- [ ] `SECURITY.md` contact/process is current.
- [ ] Artifact retention policy documented for customers.

## Distribution

- [ ] `make dist` produces binary, SBOM, and checksums.
- [ ] Source archive excludes `.fuzzfw/`, `fuzzfw-out*/`, build trees, secrets.
- [ ] `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md` included.
- [ ] Checksums signed/published according to company policy.
- [ ] Release notes state supported host/toolchain matrix and known limitations.
- [ ] Software registration/copyright holder review completed if required.
- [ ] Trademark/export review completed if required.

## Post-release

- [ ] Tag and commit hashes recorded.
- [ ] SBOM and checksums archived.
- [ ] Customer-facing known-issues list updated.
- [ ] Security advisory channel monitored.
