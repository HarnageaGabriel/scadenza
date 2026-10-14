# Contributing

Thank you for improving scadenza. Contributions must follow [CONVENTIONS.md](CONVENTIONS.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).

## Developer Certificate of Origin

Every commit must include a Developer Certificate of Origin sign-off. Create one with `git commit -s`; the `Signed-off-by` line certifies the contribution under [Developer Certificate of Origin 1.1](https://developercertificate.org/).

Pull requests are checked for a matching sign-off on every commit. If commits
were rewritten, use `git rebase --signoff` before pushing.

## Development

Install the Go version declared by `go.mod`, `golangci-lint`, and `govulncheck`, then run:

```sh
make fmt
make test
make lint
make vuln
make docs-check
make cover-floors
```

`make build` writes the CLI to `bin/scadenza`. Do not include secrets or private/customer data in source, fixtures, logs, or diagnostics.

## Pull requests

`main` is protected: every change lands through a pull request that is squash
merged, with a linear history, and the required checks (tests on Linux and
macOS, lint and generated files, vulnerability scan, GoReleaser configuration,
end-to-end on kind, CodeQL) must pass on a branch that is up to date with
`main`. Open a draft pull request early. Keep changes focused, link the issue
and describe what you tested.

## Security

Do not report vulnerabilities in public issues or pull requests. Use private
vulnerability reporting as described in [SECURITY.md](SECURITY.md). Read the
[threat model](docs/threat-model.md) before changing code that handles
credentials, Secrets, TLS probing or network scope. Changes there need extra
care and a test that proves the guarantee still holds.

## Provenance

Do not copy private, employer-owned or customer-owned code, fixtures or
documentation. Build from public documentation and original tests. Claims about
external behavior (CA/Browser Forum rules, certificate authorities,
cert-manager, cloud APIs) cite a public source or are marked `VERIFY:`. Test
fixtures captured from real services must contain no private data.

