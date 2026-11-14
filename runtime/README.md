# runtime

Native code linked into host-lifted targets. This directory is not a service
and has no Python or Go runtime dependency inside the fuzzing loop.

- `replay/` — one-input, one-process self-test driver with sanitizer coverage
  callbacks and entry-symbol reachability reporting.
- `adapters/` — place for project-specific approved hardware adapters. fuzzfw
  does not ship a universal HAL stub.

The replay driver is embedded into the `fuzzfw` binary with `go:embed`, so an
installed fuzzfw executable carries the C source it needs for host builds.
