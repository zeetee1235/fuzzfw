# Export control and trademark review prompts

This is a review checklist, not a legal classification.

## Export control

Fuzzing and vulnerability-discovery software can be dual-use. Review:

- destination countries, customers, and end users;
- whether the release includes cryptographic implementations or controlled
  technical data;
- whether customer firmware or adapter contracts are export-controlled;
- whether hosted/CI services cross borders;
- whether the company needs an export management system or license exception.

The repository intentionally contains no encryption implementation, but project
code under test may. Do not ship customer firmware in public releases.

## Trademark

Before launch:

- search `fuzzfw` as a word mark, package name, and domain in target markets;
- decide whether to register in the relevant classes;
- publish a usage policy if third parties redistribute;
- avoid implying certification or endorsement by the maintainers;
- update `NOTICE` if the legal owner changes.

## Customer contracts

Enterprise sales may require:

- security questionnaire answers;
- SBOM and vulnerability disclosure terms;
- support/warranty/indemnity terms;
- data processing and retention terms for crash inputs;
- source escrow or audit rights;
- confirmation that fuzzfw does not upload code or telemetry.

Apache-2.0 grants copyright and patent rights but does not provide support,
warranty, or indemnity. Those are commercial terms for the company to define.
