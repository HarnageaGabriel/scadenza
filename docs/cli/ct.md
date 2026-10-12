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

Set `SCADENZA_CERTSPOTTER_KEY` to an optional Cert Spotter API key. It is sent only as a Bearer authorization header and is never accepted as a flag or printed.

Results are sorted by `not_before` descending and then SHA-256 fingerprint. Subject names are lowercased, deduplicated, and sorted. CSV joins names with one space; the table shows three names followed by `+N more`. JSON follows [`scadenza.ct/v1`](../schema/ct-v1.schema.json).

`lifetime_days` is the integer number of complete 24-hour periods between `not_before` and `not_after` (fractional periods are discarded). `verdict_100d` is `ok` at 100 days or less and `exceeds` above 100 days. This is a pure lifetime check against the maximum validity for certificates issued on or after 2027-03-15; it does not decide trust or renewal readiness.

Cert Spotter entries deduplicate by `cert_sha256`. Because crt.sh JSON supplies no certificate SHA-256, crt.sh entries deduplicate by `(issuer_ca_id, serial_number)` and keep `fingerprint_sha256` empty. VERIFY: precertificate/final-certificate correlation is intentionally outside M1 and needs confirmation against CT specifications.

Failures and fallback warnings are written to stderr. When every selected source fails, the command exits 4. Invalid domains or flags exit 2.
