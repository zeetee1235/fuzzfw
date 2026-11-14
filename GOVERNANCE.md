# Governance

## Maintainers

Maintainers are listed in `AUTHORS.md`. They review contributions, security
reports, releases, and changes to public JSON contracts. The initial project is
maintained by the fuzzfw contributors.

## Decision making

- Day-to-day changes use lazy consensus in pull requests.
- Public artifact schemas, diagnostic-code semantics, licensing, security
  policy, and release process changes require explicit maintainer approval.
- A maintainer may block a change that weakens a fail-closed gate or presents
  heuristic evidence as verified.
- Security reports are handled privately and disclosed after a fix when
  appropriate.

## Releases

Releases are tagged from `main` after the release checklist passes. Pre-1.0
versions may change schemas with a version bump and changelog entry. Once a
version is published, its license remains applicable to that version.

## Contribution licensing

The current policy is DCO + Apache-2.0. A future CLA or dual-license policy
requires public notice and legal review before new contributions are accepted
under it.

## Code of conduct

See `CODE_OF_CONDUCT.md`. Enforcement contacts are the maintainers.

## Commercial use

Apache-2.0 permits commercial use and sale. The project does not provide
warranty, support, or indemnity unless a separate agreement says so. Company
distributors are responsible for their own customer terms.
