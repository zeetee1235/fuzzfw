# Schemas

Versioned JSON contracts for fuzzfw artifacts. See
`docs/reference/schemas.md` for the artifact map. Schemas use JSON Schema
2020-12 and carry an SPDX comment.

Validate a generated artifact with any draft-2020-12 validator, for example:

```sh
python3 -m pip install check-jsonschema
check-jsonschema --schemafile schemas/finding.schema.json \
  fuzzfw-out/findings/F0000000/finding.json
```

Runtime code performs semantic checks beyond schema validation. A schema-valid
artifact is not automatically a trusted finding.
