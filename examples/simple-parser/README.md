# Simple parser example

This C11 library contains one clean function (`parse_header`) and one
intentional heap-overflow fixture (`parse_packet`).

There is no `fuzzfw.toml`. A single command auto-configures CMake, discovers the
ready targets, attaches `seeds/`, and starts libFuzzer mutation:

```sh
./run.sh
# or:
../../fuzzfw check --time 30s
```

The first run creates `build/compile_commands.json`. `parse_packet` is found by
mutation: the crash input is not in `seeds/`. The expected result is exit 1 with
one `address:heap-buffer-overflow` finding under `fuzzfw-out/findings/`.

Use `corpus/` for regression replay after the initial discovery. To customize
targets, engine, or timeouts, add a `fuzzfw.toml` as described in
[configuration](../../docs/reference/configuration.md).
