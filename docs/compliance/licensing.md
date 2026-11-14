# Licensing and commercial use

## Project license

`fuzzfw` is licensed under the **Apache License, Version 2.0**. The full text is
in [LICENSE](../../LICENSE). Redistributions must preserve the license and the
attribution notices in [NOTICE](../../NOTICE).

Apache-2.0 permits:

- commercial use;
- modification and derivative works;
- redistribution in source or object form;
- sale of products or services;
- patent use under the grant in Section 3, subject to its termination terms.

It does not grant trademark rights. It also does not require the project to
offer support, warranty, or indemnity.

## What "selling the software" can mean

Apache-2.0 does not prevent a company from charging for:

- binaries, installers, or packaged distributions;
- support, maintenance, training, or integration services;
- proprietary adapters, customer-specific harnesses, or consulting;
- a hosted or managed service, if the service terms are met.

If the business requires **exclusive proprietary licensing**, that must be
decided before accepting outside contributions. Apache-2.0 rights already
granted for released code cannot be revoked. A CLA or dual-license policy is a
business/legal decision, not a code change.

## Current contribution policy

Contributions use the Developer Certificate of Origin (DCO) and are accepted
under Apache-2.0. See [CONTRIBUTING.md](../../CONTRIBUTING.md). If the company
later wants a dual-license or proprietary relicensing model, obtain a CLA and
legal review **before** accepting the relevant contributions.

## Runtime dependencies

| Component | License | Distribution |
|---|---|---|
| Go standard library | BSD-3-Clause | Linked into the Go binary |
| `github.com/pelletier/go-toml/v2` | MIT | Linked into the Go binary |
| Replay driver (this project) | Apache-2.0 | Embedded source compiled into targets |

No GPL/AGPL runtime dependency is intentionally used. Do not add one without a
license review and an explicit product decision.

## Optional external tools

| Tool | License | Relationship |
|---|---|---|
| LLVM/Clang | Apache-2.0 WITH LLVM-exception | Separate analyzer/compiler processes; optional |
| libFuzzer | Apache-2.0 WITH LLVM-exception | Linked into fuzz binaries when selected |
| honggfuzz | Apache-2.0 | Separate process; not vendored |
| CMake | BSD-3-Clause | Build tool; not distributed with fuzzfw |
| Ninja | Apache-2.0 | Build tool; not distributed with fuzzfw |

A customer distribution that bundles these tools must include their notices and
license texts. Invoking them as separate programs is not the same as vendoring
their source into fuzzfw.

## Trademark

`fuzzfw` is a working product name. Before commercial launch:

1. search trademarks and package name availability in target markets;
2. decide whether to register a word mark;
3. publish a trademark/usage policy if the project accepts external
   distributions;
4. do not imply endorsement by the fuzzfw maintainers.

## Export control

Fuzzing, binary analysis, and vulnerability discovery tools can be subject to
export-control or dual-use review depending on jurisdiction, customers, and
destination. This repository does not contain an export classification. Obtain
legal review before exporting controlled technology, encryption code, or
customer firmware artifacts.

## Customer data

Crash inputs and sanitizer logs may contain proprietary strings, keys, memory
contents, or personal data. fuzzfw has no automatic upload path, but CI artifact
storage can still move data. Agree on retention, access, encryption, and deletion
with the customer.
