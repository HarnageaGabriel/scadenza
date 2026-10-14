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
