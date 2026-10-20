# ADR 0007: JSON compatibility within 0.1.0

Status: accepted (2026-10-14)

## Context

`scadenza ct` and `scadenza scan` publish versioned JSON: `scadenza.ct/v1` and
`scadenza.scan/v1` with the schemas in `docs/schema/`. ADR 0006 (decision 9)
requires a written rule for what may change within a major `schema_version`
before 0.1.0, plus contract tests that validate output against the published
schema.

## Decisions

1. **Additive optional fields only.** Within a `schema_version`, a change may
   add a field that is required to be present in output but optional for
   consumers, or make a previously required field optional. No field is removed
   or renamed, and no type changes.
2. **New enum values are allowed only before 0.1.0.** While the version is
   pre-0.1.0, a new value in a closed enum (for example a new `findings.kind`)
   may be added within the same `schema_version`, and it must be listed in
   `CHANGELOG.md`. `scadenza.scan/v1` gains `not-compliant-at-issuance` under
   this rule.
3. **After 0.1.0, a new enum value needs a minor schema note.** A new value
   requires a note in `CHANGELOG.md`, and it must not change the meaning of any
   existing value.
4. **Consumers must treat unknown enum values as unknown.** A consumer must not
   fail on an unrecognized enum value; it must fall back to an "unknown" path,
   exactly as scadenza itself reports `unknown` and `not_checked` rather than
   guessing.
5. **Contract tests gate every release.** End-to-end `ct` and `scan` runs across
   the documented scenarios (success, partial failure, all sources failed,
   strict, Kubernetes) are validated against `docs/schema/*.json` in CI.

## Contract tests and the validator dependency

The contract test in `internal/cli` validates real command output against the
published schemas. It uses a small in-repo validator that implements only the
JSON Schema (draft 2020-12) keywords the two schemas use: `type`, `required`,
`additionalProperties`, `properties`, `items`, `enum`, `const`, `pattern`,
`minimum`, `maximum`, and `minLength`.

The intended long-term dependency is a full validator such as
`github.com/santhosh-tekuri/jsonschema/v6`. ADR 0002 requires a written
rationale for a third-party dependency; that rationale is recorded here because
ADR 0002 is frozen: the module is test-only, has no runtime footprint, is widely
used, and replaces hand-written validation logic. It could not be added in the
offline environment used for this change (`proxy.golang.org` was unreachable),
so the in-repo validator stands in until the module can be fetched. VERIFY:
adopt `jsonschema/v6` and delete the in-repo validator once the module proxy is
reachable.

## Enforcement

`tools/schemadiff` compares two JSON Schema files and reports the changes
that break the consumers of the older contract, one per line, with a JSON
pointer path and a reason. It exits 1 when it finds one and 0 otherwise.

A line that starts with `note` is informational and does not fail the run.
Decision 1 allows a name to be added to a `required` list and allows a
required name to be dropped, and decision 2 allows a new enum value, so the
tool reports those three changes as notes:

- a new enum value was added,
- a name was added to the `required` list, whether the property itself is new
  or was optional before,
- a required property became optional; decision 1 allows it, but consumers
  relying on presence may be affected, so the note says so.

The breaks are the ones of decision 1:

- a removed property,
- a type that is no longer accepted, or a `type` constraint that was added,
- a removed enum value, or an `enum` constraint that was added,
- a `pattern` that was added, or one that changed to a pattern that is not
  provably looser,
- a `minimum`, `maximum`, `minLength` or `maxLength` that was added or that
  became stricter,
- an `additionalProperties` that turned false or that became constrained by a
  schema,
- a `const` that was added or changed,
- an array `items` constraint that was added or changed,
- an `allOf`, `anyOf` or `oneOf` list that was added or whose branch count
  changed,
- a `$ref` that changed to another external target, or one that lost its
  target,
- a removed definition that is still referenced.

A new optional property and a new definition are not breaks and are not
reported. Neither is a constraint that got looser: a wider type list, a
removed `enum` constraint, a looser or removed `pattern`, a relaxed or
removed bound, an `additionalProperties` that allows extra fields again, a
removed `const`, and a removed `items`, `allOf`, `anyOf` or `oneOf` list. A
property that was removed is reported as a break alone, not also as a note
about its required entry.

The baseline is the latest stable `vMAJOR.MINOR.PATCH` tag. A prerelease such
as `v0.0.0-rc.1` is a rehearsal, not a release, and is ignored. The
`Schema compatibility` job in `.github/workflows/ci.yml` extracts
`docs/schema/*.json` from that tag and compares them with the working tree
copies, which is the diff between releases that ADR 0006 decision 9 asks
for. While no stable tag exists, the job says that there is no released
baseline yet and passes.

Run it locally with:

```sh
git show v0.1.0:docs/schema/scan-v1.schema.json > /tmp/old-scan.json
go run ./tools/schemadiff /tmp/old-scan.json docs/schema/scan-v1.schema.json
```

## Consequences

Consumers can add fields and enum values without a `schema_version` bump before
0.1.0, but they must code defensively against unknown enum values. The contract
tests fail the build when output drifts from the published schema.