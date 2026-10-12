# scadenza

Which of your public TLS certificates will not survive 100-day lifetimes?

`scadenza` is an open CLI that merges Certificate Transparency logs, live TLS handshakes, Kubernetes / cert-manager and Azure Key Vault, and tells you for each public certificate where it lives, who renews it and whether renewal is automatic.

Status: pre-alpha, study phase. See [docs/research/01-study.md](docs/research/01-study.md).

## Prova subito
The M0 skeleton currently exposes version metadata only.
Run `go run ./cmd/scadenza version --json` from a source checkout.

## Try it now (planned)

```sh
scadenza ct example.com
```

Licence: Apache-2.0.
