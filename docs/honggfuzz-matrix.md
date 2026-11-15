# honggfuzz validation matrix

fuzzfw's normal `integration honggfuzz` tests run against the `honggfuzz`,
`hfuzz-clang`, and `hfuzz-clang++` binaries on `PATH`.

Validated in this repository:

| honggfuzz ref | Result |
|---|---|
| `940b958dfeb6f9131fd846cae31fcc0fe996ae98` | end-to-end integration tests pass |
| `2.6` (`83a8415a372d84dcc69ac1e2c2f152190bcf76d1`) | operator-run; see below |

Older releases need `binutils-devel` (for `bfd.h`) and
`libunwind-ptrace` headers, and may need `-Werror` disabled for newer compilers.
Those dependencies are intentionally not part of fuzzfw.

Run the operator matrix:

```sh
scripts/test-honggfuzz-matrix.sh
# or a custom set:
HFUZZ_REFS="ref1 ref2" JOBS=4 scripts/test-honggfuzz-matrix.sh
```

A matrix success means the tagged integration suite passes with that honggfuzz
build; it does not claim every upstream commit is compatible.
