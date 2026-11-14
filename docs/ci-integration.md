# CI integration

## Contract

`fuzzfw check` is the CI gate. It writes `summary.json`, `junit.xml`,
`summary.md`, `diagnostics.json`, and `build-info.json`, and returns:

| Exit | Meaning | CI action |
|---|---|---|
| `0` | Required checks completed; no new reproduced target finding | Pass |
| `1` | New host-reproduced target finding | Fail |
| `2` | Build/environment/self-test failure or required check incomplete | Fail |
| `3` | Invalid configuration or CLI usage | Fail |

JUnit XML does not control the process exit code. Always preserve the command's
exit status, including on GitLab where JUnit is only a report artifact.

## GitHub Actions

```yaml
name: fuzzfw
on: [pull_request]
permissions:
  contents: read
jobs:
  fuzz:
    runs-on: ubuntu-24.04
    timeout-minutes: 25
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - name: Install host toolchain
        run: sudo apt-get update && sudo apt-get install -y clang cmake ninja-build
      - name: Build fuzzfw
        run: make build
      - name: Generate compilation database
        run: cmake -S . -B build -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
      - name: Run bounded fuzz check
        run: ./fuzzfw check --time 600 --output fuzzfw-out
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: fuzzfw-results
          path: fuzzfw-out/
```

Run untrusted PR code only on an ephemeral, least-privilege runner or in a
container. Do not expose secrets to the fuzzing job.

## GitLab CI

```yaml
fuzzfw:
  image: ubuntu:24.04
  timeout: 25m
  script:
    - apt-get update && apt-get install -y clang cmake ninja-build golang-go
    - make build
    - cmake -S . -B build -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    - ./fuzzfw check --time 600 --output fuzzfw-out
  artifacts:
    when: always
    paths:
      - fuzzfw-out/
    reports:
      junit: fuzzfw-out/junit.xml
```

GitLab may not fail a job because of JUnit results; the `script` exit status is
the gate.

## Baseline policy

- First run with no baseline: all reproduced findings are new.
- `--bootstrap-baseline` explicitly approves the current findings.
- Commit the baseline JSON or store it as a protected CI artifact.
- Do not auto-ignore a finding by name alone; the baseline uses a normalized
  fingerprint of sanitizer kind, origin, target, build profile, and normalized
  top frames.

## Artifact retention

Findings include raw crash inputs and sanitizer logs. They may contain customer
secrets. Set retention, access, and encryption policy accordingly. At minimum,
preserve for a reproduced finding:

- `finding.json`
- `input.bin`
- `sanitizer.log`
- `repro.json`
- `replay.sh`

## Recommended jobs

| Job | Budget | Policy |
|---|---|---|
| PR | 5–15 minutes | Required targets + existing corpus replay + short fuzzing |
| Nightly | 1–6 hours | All registered targets, longer budgets, corpus expansion |
| Release | Team policy | Full required targets, baseline review, ABI/adapter review |

`changed-only` optimization is not a P0 default; it can create unexamined
coverage. Required targets are explicit in configuration.
