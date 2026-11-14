# ADR 0005: fail-closed CI and explicit baselines

- Status: accepted
- Date: 2026-11-15

## Context

Security tooling that reports success when a required target did not run creates
false assurance. Flaky or non-reproduced findings are also dangerous to treat as
confirmed product defects.

## Decision

- Required targets must build, self-test, reach the entry point, and execute.
- Zero required targets is a configuration error.
- Missing required work exits 2.
- Only a new host-reproduced target finding exits 1.
- Harness/adapter failures exit 2 and are not promoted to product findings.
- Baseline comparison is explicit; the first run treats all reproduced findings
  as new unless `--bootstrap-baseline` is approved.
- JUnit output never replaces the exit code.

## Consequences

- CI may fail when a runner is misconfigured, which is intentional.
- Baselines need review and ownership.
- Finding fingerprints must be normalized and stable; otherwise baselines churn.
