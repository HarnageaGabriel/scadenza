# Changelog

All notable changes are listed here. Format: Keep a Changelog.

## Unreleased
- Add a read-only Kubernetes source to `scadenza scan` (`--kube`): read `kubernetes.io/tls` Secrets (only `tls.crt`, key never touched) and cert-manager `Certificate` resources with client-go and a dynamic client, merge them by SHA-256 fingerprint into the existing inventory, report issuer type and renewal facts, and resolve owners only from labels, annotations, namespaces, or an optional mapping file. Additive `scadenza.scan/v1` fields (`owners`, `kubernetes`, `sources_used: kube`, `verdict_100d: not_applicable`, `kube_only`), diagnostics `SCD-0014`-`SCD-0019`, a minimal ClusterRole in `deploy/rbac/`, ADR 0005, and a kind + cert-manager CI workflow.- Add `scadenza scan`: correlate Certificate Transparency issuances with live TLS handshakes by SHA-256 fingerprint, report expected-versus-observed differences, probe explicitly named hosts only (wildcards listed as unresolved, `--max-hosts` cap), and emit table/JSON/CSV following `scadenza.scan/v1`.
- Fix M1 review findings: redirect and Authorization hardening, strict Cert Spotter pagination and limits, exact 100-day verdict, CSV formula-injection guard, bounded Retry-After handling (delta-seconds and HTTP-date), total sort order, internal-error exit code, inverted-validity rejection, typed diagnostic schema, and scorecard SARIF upload.
- Add `scadenza ct <domain>` with Cert Spotter and crt.sh fallback, deterministic table/JSON/CSV output, bounded HTTP behavior, diagnostics, schemas, and offline fixtures.
- Repository bootstrap and study notes.
