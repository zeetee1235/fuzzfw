# ADR 0003: deterministic canonical artifacts

- Status: accepted
- Date: 2026-11-15

## Context

If plans, harnesses, and finding identities change across runs, baselines and
CI reproducibility become meaningless. The specification requires stable plan
and harness hashes.

## Decision

- JSON artifacts are canonicalized with sorted keys and stable collection
  ordering.
- Plan/harness IDs are content hashes and exclude timestamps.
- Generated source contains no random identifiers or timestamps.
- Git dirty-state digests only include paths inside the analyzed project and
  generated artifact directories are excluded by the repository ignore rules.
- Finding fingerprints use normalized frames and build/profile identity, not raw
  addresses or line-only values.

## Consequences

- Artifacts can be diffed and reviewed in source control.
- Developers must consciously bump a schema version when field semantics change.
- Some environment-specific facts are recorded in build-info instead of the plan
  identity.
