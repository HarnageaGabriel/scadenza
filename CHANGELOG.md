# Changelog

All notable changes are listed here. Format: Keep a Changelog.

## Unreleased
- Add `scadenza scan`: correlate Certificate Transparency issuances with live TLS handshakes by SHA-256 fingerprint, report expected-versus-observed differences, probe explicitly named hosts only (wildcards listed as unresolved, `--max-hosts` cap), and emit table/JSON/CSV following `scadenza.scan/v1`.
- Fix M1 review findings: redirect and Authorization hardening, strict Cert Spotter pagination and limits, exact 100-day verdict, CSV formula-injection guard, bounded Retry-After handling (delta-seconds and HTTP-date), total sort order, internal-error exit code, inverted-validity rejection, typed diagnostic schema, and scorecard SARIF upload.
- Add `scadenza ct <domain>` with Cert Spotter and crt.sh fallback, deterministic table/JSON/CSV output, bounded HTTP behavior, diagnostics, schemas, and offline fixtures.
- Repository bootstrap and study notes.
