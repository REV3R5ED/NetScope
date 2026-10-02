# Versioned JSON schemas

Every NetScope command with JSON output has a JSON Schema document bundled at
`src/netscope/schemas/<command>.schema.json` and shipped inside the package.
`netscope schema COMMAND` prints the document:

```bash
netscope schema tls
netscope schema tcp-summary
```

Available documents: `interfaces`, `address`, `network`, `dns`, `tcp`,
`tcp-summary`, `path`, `ping`, `tls`. (The `check` command emits the
underlying check's report, so it is covered by that check's schema.)

## Contract testing

`tests/test_schema_contract.py` validates a representative success and
failure payload for every command against its schema, so CI fails if a code
change alters the JSON shape without updating the schema. The validator is a
small stdlib-only subset implementation (`netscope.schemas`) supporting
`type`, `enum`, `minimum`/`maximum`, `required`, `properties`, `items`, and
`additionalProperties`.

## Versioning policy

Each document carries an integer `version` and a `$id` containing `/vN/`:

- **Additive changes** (new optional properties): bump the document's
  `version` in place.
- **Breaking changes** (removed, renamed, or retyped properties): publish a
  new `/vN+1/` document while the previous version keeps shipping.

Consumers should pin the `$id` version they validate against.
