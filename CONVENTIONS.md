# Conventions

These rules are mandatory for human and automated contributors.

## Architecture

- `cmd/` contains wiring only; `internal/cli` owns command behavior.
- `internal/diag` is pure and must not import `net/http`, `os`, or `os/exec`.
- Interfaces belong to consumer packages. Avoid package-level mutable state except build metadata and immutable embedded registries.
- Only `internal/clock` may call `time.Now`.

## Diagnostics and output

- Every user-visible problem has a registered stable `SCD-NNNN` code and generated documentation page.
- Human tables are the default for future data commands; JSON and CSV schemas must be stable and versioned.
- Observable output is deterministic. Sort map-derived values before rendering.
- Stdout is command data; logs and diagnostics go to stderr. Never log secrets.

## Errors, I/O, and security

- Wrap errors with `%w`; never compare error strings.
- Blocking or I/O operations accept `context.Context` first.
- The program is read-only, performs no telemetry, and never weakens TLS verification.

## Tests and dependencies

- Prefer table-driven tests and `go-cmp` structural diffs.
- Product packages have a 70% coverage floor.
- Third-party dependencies require a written rationale in an ADR.
- Mark claims not verified against an official source with `VERIFY:`.
