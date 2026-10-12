# Study notes (2026-10-12)

Status: first pass. Items marked `VERIFY:` are not confirmed against an official source and each becomes a tracked issue.

## Deadlines (CA/B Forum SC-081v3, approved 2025-04-11)
- 2026-03-15: max validity 200 days (already in force).
- 2027-03-15: 100 days. Target: first release by 2027-02.
- 2029-03-15: 47 days, DCV reuse 10 days.
- VERIFY: intermediate DCV reuse values (200 / 100 days) - only secondary sources so far. Read the ballot text and the Baseline Requirements.
- Applies to publicly trusted certificates only; private PKI is inventoried without a calendar.

## Source 1 - Certificate Transparency
- crt.sh has no official API; the JSON output is undocumented, rate limits are folklore (~5 req/min/IP, answers 502 or empty arrays rather than 429). Unsuitable as the only backend.
- Cert Spotter (SSLMate) is a documented API. VERIFY: free-tier quota, key requirement, pagination.
- Options: pluggable `ctsource` interface with crt.sh and Cert Spotter first; RFC 6962 / static-ct-api direct log reading is out of scope for v0.
- Fixtures: record real responses, anonymise, keep under `testdata/ct/`.
- Precertificate and final certificate share a name set but not a fingerprint: correlate by (issuer, serial) for CT entries, by SHA-256 of the DER for live certs. VERIFY the precert/cert dedup rule (RFC 6962 poison extension).

## Source 2 - TLS handshake
- Only hosts given explicitly or discovered from CT names; SNI always set; no IP range scans (hard constraint).
- Wildcard names from CT are not scannable: list them as `unresolved`, never guess hosts.
- Must tolerate: no cert, expired cert, self-signed, SNI-required, timeouts. Use InsecureSkipVerify only to read the chain, never to trust it (document as an ADR; golangci gosec exception scoped to one file).

## Source 3 - Kubernetes
- Secrets of type `kubernetes.io/tls`: parse `tls.crt`, never log or retain `tls.key`; do not even read it (drop the key from memory right after decode, or use field selection where possible).
- cert-manager `Certificate`: `spec.issuerRef`, `spec.secretName`, `status.notBefore/notAfter/renewalTime`, `Ready` condition. Issuer / ClusterIssuer with `spec.acme` means automatic ACME renewal.
- Go: import only `github.com/cert-manager/cert-manager/pkg/apis/...`; the project gives no compatibility guarantee for other packages. Prefer dynamic/unstructured client to avoid the heavy dependency; decide in ADR 0002.
- Owner: labels, annotations and namespace, via config mapping. Never inferred.

## Source 4 - Azure Key Vault (first cloud)
- Policy carries `lifetimeActions`: action `AutoRenew` or `EmailContacts`, trigger by days-before-expiry or lifetime percentage.
- Classification: AutoRenew + issuer that is an integrated public CA (DigiCert/GlobalSign) => automatic; EmailContacts only => manual; self-signed or "Unknown" issuer => unknown/private.
- Go SDK: `github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates`. VERIFY exact types.
- Read-only role needed: `Key Vault Certificates Officer` is too broad; document `Key Vault Reader` + `certificates/list,get` access policy or RBAC `Key Vault Certificate User`. VERIFY.

## Core domain
- `Certificate` keyed by SHA-256 fingerprint; `Observation{source, location, owner?, renewal}`.
- Renewal class: automatic | manual | unknown.
- "Survives 100 days?" verdict: lifetime vs 100 days, plus renewal class, plus renewal lead time (renewBefore vs validity: cert-manager default renews at 2/3 of duration, fine at 100d; flag fixed `renewBefore` > validity/2).
- Diff: expected (CT) vs observed (live/managed): `ct-only`, `live-only`.
- Diagnostic codes `SCD-NNNN`, one docs page each (generated, like trasloco's docsgen).

## Risks
- CT backend availability and quota.
- cert-manager API drift.
- Pre/final cert correlation errors producing false "ct-only".
- Wildcards.

## Proposed milestones
- M0 Skeleton: cobra CLI, diag registry, version, CI, lint, docs gen, governance files.
- M1 `scadenza ct <domain>` (the "Prova subito"): crt.sh + Cert Spotter, table/JSON/CSV, fixtures.
- M2 TLS handshake scanner + correlation by fingerprint.
- M3 Kubernetes Secrets + cert-manager (kind e2e).
- M4 Azure Key Vault.
- M5 Classification + expected-vs-observed diff + owner mapping.
- M6 Hardening: fuzzing, SARIF if useful, GoReleaser, Homebrew, krew, Scorecard.
