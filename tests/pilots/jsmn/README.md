# jsmn firmware pilot

This pilot runs fuzzfw against the real `jsmn` embedded JSON tokenizer.

- Upstream: https://github.com/zserge/jsmn
- Commit: `25647e692c7906b96ffd2b05ca54c097948e879c`
- License: MIT (see `LICENSE.jsmn`; the original header is preserved in
  `include/jsmn.h`)

`jsmn` exposes `jsmn_parse(jsmn_parser *, const char *, size_t, jsmntok_t *,
unsigned int)`. The token array and parser object are caller-owned, so this
pilot uses the supported explicit-wrapper escape hatch to keep those objects on
the stack and call the real parser. The wrapper does not contain parser logic.

The project is intentionally self-contained so the pilot runs without network
access:

```sh
cmake -S . -B build -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build
fuzzfw check --engine replay --time 1s
```
