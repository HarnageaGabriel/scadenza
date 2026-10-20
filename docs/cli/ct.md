# `scadenza ct`

`scadenza ct <domain>` lists publicly logged certificates for a DNS domain. It is read-only and requires no configuration. Cert Spotter is queried first and crt.sh is used when the preferred source is unavailable, rate-limited, or malformed.

```sh
scadenza ct example.com
scadenza ct example.com --format json
scadenza ct example.com --source crtsh --expired
```

Options:

- `--source certspotter,crtsh` selects and orders sources.
- `--include-subdomains` includes subdomains and is true by default.
- `--expired` retains certificates whose `not_after` is earlier than the current time.
- `--format table|json|csv` selects table (default), versioned JSON, or CSV.
- `--max-results N` limits output to 1000 certificates by default.
- `--now RFC3339` fixes the evaluation instant, so the same input gives the
  same output and you can evaluate against a future date. It also sets
  `generated_at`.

Set `SCADENZA_CERTSPOTTER_KEY` to an optional Cert Spotter API key. It is sent only as a Bearer authorization header and is never accepted as a flag or printed.

Results are sorted by `not_before` descending, then fingerprint, dedup key, issuer, serial, and joined names (a total order, so output is deterministic). Subject names are lowercased, deduplicated, and sorted. CSV joins names with one space; the table shows three names followed by `+N more`. JSON follows [`scadenza.ct/v1`](../schema/ct-v1.schema.json).

`lifetime_days` is the integer number of complete 24-hour periods between `not_before` and `not_after` (fractional periods are discarded). `verdict_100d` is computed from the exact, unrounded validity duration: `ok` when it is at most 100*24h and `exceeds` when strictly greater (100d+1s exceeds). So the floored `lifetime_days` is display only; for example 100d+1s shows `100` but is `exceeds`. This is a pure lifetime check against the maximum validity for certificates issued on or after 2027-03-15; it does not decide trust or renewal readiness.

Cert Spotter entries deduplicate by `cert_sha256`. Because crt.sh JSON supplies no certificate SHA-256, crt.sh entries deduplicate by `(issuer_ca_id, serial_number)` and keep `fingerprint_sha256` empty. VERIFY: precertificate/final-certificate correlation is intentionally outside M1 and needs confirmation against CT specifications.

Each certificate also carries a `policy` object computed from `not_before`: the maximum validity in force at issuance, whether the exact lifetime fits it (`compliant_at_issuance`), the next scheduled limit and its effective date, and whether the lifetime fits it. Certificate validity follows the BR section 6.3.2 history: 1186 days before 2018-03-01, 825 days before 2020-09-01, 398 days before 2026-03-15, then 200, 100, and 47 days (SC-081v3); `verdict_100d` is unchanged. See [`scadenza scan`](scan.md#dated-policy).

CSV output sanitizes every text cell before it is written: tabs, carriage returns, and line breaks become a single space, other control characters are dropped, and a cell is capped at 256 display columns. A cell that begins with `=`, `+`, `-`, or `@`, also after leading whitespace, is prefixed with a single quote to prevent spreadsheet formula injection. The table output is sanitized and capped the same way but carries no formula guard, and JSON output is data: the encoder escapes control characters itself and truncates nothing.

Cert Spotter pagination requires a non-empty cursor that advances on every page and stops after 1000 pages (SCD-0004 otherwise). On HTTP 429 the Retry-After delay (seconds or HTTP-date, clamped to 30s) is honored for one retry, then the source is reported rate-limited (SCD-0003) and fallback applies. Redirects to a different scheme or host are refused. A record whose `not_after` precedes `not_before` fails the source response as malformed (SCD-0004).

Failures and fallback warnings are written to stderr. When every selected source fails, the command exits 4. Invalid domains or flags exit 2. An interrupted run exits 130 and writes no report.

See also [`scadenza scan`](scan.md) and [`scadenza version`](version.md).
