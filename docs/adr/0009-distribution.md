# ADR 0009: Distribution

## Decision

For 0.1.0, distribute scadenza through GitHub Releases. GoReleaser produces
Linux, macOS, and Windows artifacts, `checksums.txt`, keyless cosign signing,
and build provenance. Releases remain drafts for maintainer review.

The Homebrew tap is planned but not enabled: it needs
`HarnageaGabriel/homebrew-tap` and a repository token secret. `go install`
remains supported.

There is no krew plugin for 0.1.0 because scadenza is not Kubernetes-only.
Revisit later; a thin `kubectl-scadenza` alias is possible, while krew needs a
plugin manifest and a `kubectl-` binary name.

## Consequences

Users can verify immutable checksums, keyless signatures, and provenance before
installing. The maintainer must explicitly publish each reviewed draft.
