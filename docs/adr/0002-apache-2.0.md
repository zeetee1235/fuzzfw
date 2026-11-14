# ADR 0002: Apache-2.0 project license

- Status: accepted
- Date: 2026-11-15

## Context

The project may be sold to enterprises, embedded in commercial services, or
offered under separate support terms. It also wants broad open-source adoption
and patent clarity. Optional external fuzzers use Apache-2.0 or LLVM's
Apache-2.0-with-exception license.

## Decision

Use Apache-2.0 for fuzzfw. Do not add GPL/AGPL runtime dependencies. Invoke
external tools as separate processes unless a future component explicitly
documents a different linking policy.

## Consequences

- Commercial use, modification, redistribution, and sale are permitted under
  Apache-2.0.
- Redistributors must preserve LICENSE/NOTICE obligations.
- A company that wants exclusive proprietary terms or a dual-license model must
  establish a contributor policy (DCO vs CLA) and obtain legal review before
  relying on contributed code.
- The project name is a working name; trademark registration is separate.
