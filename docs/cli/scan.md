# `scadenza scan`

`scadenza scan` collects certificates from Certificate Transparency logs and
live TLS handshakes, correlates them by SHA-256 fingerprint ("one certificate,
every place it appears"), and reports expected-versus-observed differences. It
is read-only, performs no telemetry, and needs no configuration.

```sh
scadenza scan --domain example.com
scadenza scan --domain example.com --format json
scadenza scan --domain example.com --host www.example.com:8443 --source crtsh
scadenza scan --from-ct=false --hosts-file hosts.txt
```

## What gets probed

Only hosts named explicitly (`--host`, `--hosts-file`, or a `--domain`) or
derived from the non-wildcard Certificate Transparency subject names under an
explicitly given domain. There is no IP-range scanning and no DNS enumeration
beyond resolving the host names that are actually probed.

Wildcard names (`*.example.com`) are never probed. They are listed in
`unresolved` with reason `wildcard` and reported as `SCD-0008`. Names beyond the
`--max-hosts` cap (default 200) are listed in `unresolved` with reason
`host-cap` and reported as `SCD-0009`; the remaining hosts are simply not
probed.

## Options

- `--domain name` selects a domain to query in CT and to probe. Repeatable.
- `--host h[:port]` probes an explicit host. Repeatable; `--port` supplies the
  default.
- `--hosts-file f` reads one host per line; blank lines and everything after
  `#` are ignored.
- `--from-ct` (default true) derives probe hosts from non-wildcard CT names.
- `--port` (default 443), `--concurrency` (default 8), `--timeout` (default 5s),
  `--max-hosts` (default 200).
- `--source certspotter,crtsh` selects and orders CT sources.
- `--format table|json|csv` selects table (default), versioned JSON, or CSV.

## Correlation rules

Certificates are keyed by SHA-256 fingerprint when it is available. Cert Spotter
supplies fingerprints, so its records correlate directly. crt.sh JSON supplies
no fingerprint; those records correlate to a live certificate by normalized
issuer name plus serial number, and only when the serial is present and equal.
Otherwise each is kept separate and reported as `unknown`. VERIFY:
precertificate/final-certificate correlation (RFC 6962) is not implemented; a
precertificate and its final certificate share names but not fingerprints.

The live certificate is verified separately against the system roots (see
[ADR 0004](../adr/0004-tls-verification-policy.md)); `public` is `true`, `false`,
or `null` (unknown for CT-only certificates). `exceeds` is computed from the
exact, unrounded validity duration, as in `scadenza ct`.

## Findings

Findings are deterministic and sorted. The kinds are:

- `matched` - both issued in CT and presented live.
- `ct_only` - still valid in CT and not presented by any probed host, compared
  only over names that were actually probed.
- `live_only` - presented by a probed host but absent from CT; the detail is
  marked `private_or_untrusted` when the chain did not verify.
- `not_checked` - undecidable, for example a wildcard name, an unprobed or
  failed probe name, or a certificate that already expired.
- `unknown` - no fingerprint or serial number, so it cannot be correlated.
- `exceeds-100d` - the certificate validity exceeds 100 days.

Never infer: anything undecidable is `not_checked` or `unknown`.

## Exit codes

`0` when no `ct_only`, `live_only`, or `exceeds-100d` finding exists (matched and
`not_checked` findings do not affect the exit status). `3` when one of those
findings exists. `4` when every selected source was unavailable. `2` on usage
errors. See [exit codes](../exit-codes.md).

## Output

JSON follows [`scadenza.scan/v1`](../schema/scan-v1.schema.json) and contains
`certificates`, `findings`, `unresolved`, `probe_errors`, and `diagnostics`.
The table prints the certificates followed by a findings summary. CSV emits one
row per (certificate, observation) and reuses the `scadenza ct` formula-injection
escaping (a leading single quote for cells starting with `=`, `+`, `-`, `@`, tab,
or carriage return).