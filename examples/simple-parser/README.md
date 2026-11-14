# Simple parser example

This C11 library contains one clean function (`parse_header`) and one
intentional heap-overflow fixture (`parse_packet`). It demonstrates the
complete fuzzfw flow:

```sh
cmake -S . -B build -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build
../../fuzzfw check --engine replay --output fuzzfw-out
```

The crash seed is in `corpus/`, not the normal seed set, so the build gate
passes and the corpus regression exposes the finding. With
`ci.engine = "libfuzzer"` or `"honggfuzz"` the check also mutates inputs.
