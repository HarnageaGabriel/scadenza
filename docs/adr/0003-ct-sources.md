# ADR 0003: Prefer Cert Spotter with crt.sh fallback

Status: accepted

## Decision

M1 queries Cert Spotter first and crt.sh second. A consumer-owned source interface keeps backend response details out of command behavior without creating a general plugin system. The first successful selected source supplies the result set; a failed source produces a stable diagnostic before fallback.

Cert Spotter has a documented issuance endpoint, cursor pagination, expanded DNS names and issuer metadata, and certificate SHA-256 fingerprints. Its optional API key is read from `SCADENZA_CERTSPOTTER_KEY` and unauthenticated quotas are not assumed.

crt.sh is a useful independent fallback, but its JSON query interface is undocumented. The repository includes a real captured 502 response in `testdata/ct/crtsh-502.html`, evidence that it can be unavailable under load, so it is not the default primary source. VERIFY: crt.sh has no published availability or rate-limit contract; re-check if official documentation appears.

Both clients retain TLS verification, bounded 32 MiB bodies, explicit timeouts, context cancellation, source-specific request pacing, and at most three attempts for HTTP 502/503/504.

## Consequences

Output remains deterministic even when upstream order changes. Cert Spotter records deduplicate by certificate SHA-256; crt.sh records use issuer CA ID plus serial number and cannot provide a fingerprint. Precertificate/final-certificate correlation remains a documented M1 limitation.
