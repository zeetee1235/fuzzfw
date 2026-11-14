# Approved adapter models

Adapters in this directory are examples/templates, not automatic stubs. A real
customer adapter must be registered in `fuzzfw.toml` with a contract JSON file
and must be reviewed for:

- exact prototype and calling convention;
- maximum bytes written;
- return status and error paths;
- required initialized context;
- time, interrupt, DMA, and nondeterminism limits.

`fuzzfw` rejects placeholder adapters such as `return 0;` when the contract
claims an input source.
