# scadenza

Which of your public TLS certificates will not survive 100-day lifetimes?

`scadenza` is an open CLI that merges Certificate Transparency logs, live TLS handshakes, Kubernetes / cert-manager and Azure Key Vault, and tells you for each public certificate where it lives, who renews it and whether renewal is automatic.

Status: pre-alpha, study phase. See [docs/research/01-study.md](docs/research/01-study.md).

## Prova subito

```sh
scadenza ct example.com
scadenza scan --domain example.com
scadenza scan --kube --kube-context prod
```

From a source checkout, use `go run ./cmd/scadenza ct example.com`. The commands need no configuration; use `--format json` or `--format csv` for machine-readable output. `scadenza scan` correlates Certificate Transparency issuances with live TLS handshakes (`--domain` and/or `--host`) and reports expected-versus-observed differences.

With `--kube`, `scadenza scan` also reads `kubernetes.io/tls` Secrets and cert-manager `Certificate` resources read-only (`list`/`get` only, never `tls.key`), merges them into the same fingerprint-correlated inventory, and takes owner information only from labels, annotations, namespaces, or an optional ownership mapping file (see [docs/ownership.md](docs/ownership.md)).

Licence: Apache-2.0.
