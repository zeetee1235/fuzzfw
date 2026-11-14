# Software registration evidence checklist

**Not legal advice.** Software copyright registration requirements vary by
jurisdiction and by whether the work is published, commissioned, or jointly
owned. Confirm the current requirements with the relevant authority and counsel.

For Korean software copyright registration (프로그램 등록), teams commonly need a
program summary, source code listing, authorship/ownership evidence, and version
identification. The exact format and deposit rules change; use the current
official guidance.

## What to preserve in this repository

- **Authorship history:** Git commits with DCO `Signed-off-by` lines and
  `AUTHORS.md`.
- **Copyright notices:** `LICENSE`, `NOTICE`, SPDX headers, and package
  metadata. Do not bulk-replace the copyright holder after contributors join
  without a legal basis.
- **Version identity:** a release tag, changelog entry, `internal/version`,
  SBOM, and checksums.
- **Source listing:** the source tree at the tag, excluding generated build
  output and customer data.
- **Build instructions:** `Makefile`, `go.mod`, `analyzer/CMakeLists.txt`, and
  the quick-start guide.
- **Substance:** a concise description of the program's purpose, architecture,
  languages, and major functions.
- **Optional registration deposit:** a source listing of the requested length
  with the required header page; keep the full archive for the record.

## Pre-registration checklist

1. Choose the legal copyright holder (individual or company) and confirm
   assignment/employment ownership for all contributors.
2. Confirm the Go module path and package metadata match the final company
   namespace. The repository default `github.com/fuzzfw/fuzzfw` is a
   placeholder.
3. Decide whether the release is published or unpublished for registration
   purposes.
4. Freeze a clean release tag and create a source archive.
5. Run `make dist` and `make sbom`; record SHA-256 checksums.
6. Confirm that no customer firmware, adapter, crash input, or secret is in the
   public source archive.
7. Prepare the program summary and identify the claimed version.
8. Have counsel review contributor, license, and ownership records.
9. Store the registration receipt and deposited source hash in the company
   records.

## What not to claim

- Do not describe fuzzfw as proving MCU safety.
- Do not claim ownership of LLVM/Clang, honggfuzz, Go, or third-party libraries.
- Do not remove third-party notices from distributed artifacts.
