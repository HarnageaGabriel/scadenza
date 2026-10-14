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
scadenza scan --domain example.com --strict --min-coverage 90 --fail-on live_only
scadenza scan --kube --group-by owner
scadenza scan --config scadenza.yaml
scadenza scan --domain example.com --now 2027-04-01T00:00:00Z --format json
```

## What gets probed

Only hosts named explicitly (`--host`, `--hosts-file`, or a `--domain`) or
derived from the non-wildcard Certificate Transparency subject names under an
explicitly given domain. There is no IP-range scanning and no DNS enumeration
beyond resolving the host names that are actually probed.

Wildcard names (`*.example.com`) are never probed. They are listed in
`unresolved` with reason `wildcard` and reported as `SCD-0008`. Explicitly named
targets (`--host`, `--hosts-file`, and `--domain`) are always probed; the
`--max-hosts` cap (default 200) only ever trims CT-derived hosts. Trimmed
derived names are listed in `unresolved` with reason `host-cap` and reported as
`SCD-0009`; the remaining hosts are simply not probed.

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
- `--strict` exits 5 (`SCD-0020`) when any source is partial or failed, any probe
  failed, or any item was not checked.
- `--min-coverage <0-100>` exits 5 (`SCD-0020`) when the coverage ratio is below
  this percentage. With a positive threshold, a target-less scan also fails when
  a requested source is not `ok`, or when no requested source produced data.
- `--fail-on k1,k2` selects the finding kinds that cause exit 3. One or more of
  `ct_only`, `live_only`, `exceeds-100d`, `not-compliant-at-issuance`,
  `renew-before-exceeds-lifetime`, `renewal-degraded`,
  `renew-before-loop-at-next-limit`, `duration-exceeds-next-limit`,
  `manual-renewal-after-limit`, `renewal-config-invalid`, or `none` alone.
  Default
  `live_only,not-compliant-at-issuance,renew-before-exceeds-lifetime,renewal-degraded`.
- `--group-by owner|names|none` (default `none`) groups the table rows by the
  first owner or the first certificate name. It never changes JSON or CSV.
- `--now RFC3339` fixes the evaluation instant. The same input then gives the
  same output, and you can evaluate against a future date. It also sets
  `generated_at`.
- `--config path` reads an explicit YAML file; see
  [configuration](../configuration.md). It is never auto-loaded.
- `--kube` also reads TLS Secrets and cert-manager Certificates from a
  Kubernetes cluster, read-only.
- `--kube-context name`, `--kubeconfig path`, `--namespace ns` (repeatable,
  default all namespaces), `--ownership-file path`, `--kube-qps 5` configure the
  Kubernetes source. They require `--kube`.

## Kubernetes source

`scan --kube` adds a read-only Kubernetes source. It lists Secrets with the
server-side field selector `type=kubernetes.io/tls`, reads only `tls.crt`, and
parses the PEM chain. The leaf's SHA-256 DER fingerprint merges it into the same
inventory as Certificate Transparency and live handshakes. `tls.key` is dropped
from the object as soon as the list response is decoded and is never decoded,
copied, logged, or retained.

It also reads cert-manager `Certificate` resources at `cert-manager.io/v1` and
reports the issuer kind and name, the resolved issuer type (`acme`, `ca`,
`selfSigned`, `vault`, `venafi`, `external`, or `unknown`, taken only when
exactly one recognized `spec` key has a map value), the ACME directory server URL, `spec.duration`,
`spec.renewBefore`, `spec.renewBeforePercentage`, `status.notAfter`,
`status.renewalTime`, and the `Ready` condition, and the
`cert-manager.io/certificate-name` annotation of a TLS
Secret. M4b classifies renewal from these facts without re-reading the cluster;
see [renewal](../renewal.md). Private keys and `privateKeySecretRef` targets are
never read.

Kubernetes certificates that do not verify against the system roots keep the
inventory entry but get no 100-day verdict: `verdict_100d` is `not_applicable`
and `public` stays `null` (unknown). A certificate seen only in Kubernetes is
reported with the finding kind `kube_only`.

## Renewal

Every certificate carries `renewal` `{mode, health, evidence, risks}`. `mode` is
`automatic`, `manual`, or `unknown`; `health` is `healthy`, `degraded`,
`configured`, or `unknown`. Missing evidence is `unknown`, never a guess. The
full rules, sources, and risk kinds are in [renewal](../renewal.md). The scan
document also carries a top-level `owners` workload summary with the manual
renewals per year at 200, 100, and 47 days.

Owners come only from labels, annotations, namespaces, and an optional mapping
file; see [ownership](../ownership.md). Each owner records its source in the
`owners` array (`owner`, `owner_source`, `location`). A namespace annotation is
reported as `namespace-annotation` and a namespace label as `namespace-label`.

Credentials and kubeconfig content are never printed. Reads use only `list` and
`get`; the minimal RBAC is in
[`deploy/rbac/scadenza-readonly.yaml`](../../deploy/rbac/scadenza-readonly.yaml).
Kubernetes client errors are reduced to HTTP status, StatusReason, resource
kind, and namespace; their raw text is never printed. A 401 makes the
Kubernetes source unavailable. A 403 is a partial warning when at least one
requested Secret or Certificate list succeeds; if none succeeds, the source is
unavailable. An empty successful list still counts as a successful source read.

Run the source against a cluster (the CI-only kind test does this):

```sh
scadenza scan --kube --kube-context kind-scadenza-e2e --format json
```

## Correlation rules

Certificates are keyed by SHA-256 fingerprint when it is available. Cert Spotter
supplies fingerprints, so its records correlate directly. crt.sh JSON supplies
no fingerprint; those records correlate to a live certificate by normalized
issuer name plus serial number, and only when the serial is present and equal.
Otherwise each is kept separate and reported as `unknown`. VERIFY:
precertificate/final-certificate correlation (RFC 6962) is not implemented; a
precertificate and its final certificate share names but not fingerprints.

Every certificate states how strong its correlation is in `correlation_method`:

- `sha256` - the entry is keyed by a SHA-256 fingerprint.
- `issuer_serial` - it was matched by issuer and serial number.
- `unresolved` - nothing correlated the record.

The value is the **weakest** evidence that placed the certificate in the
inventory, so a merged entry never claims more certainty than its least certain
observation.

The live certificate is verified separately against the system roots (see
[ADR 0004](../adr/0004-tls-verification-policy.md)); `public` is `true`, `false`,
or `null` (unknown for CT-only certificates). `exceeds` is computed from the
exact, unrounded validity duration, as in `scadenza ct`.

## Dated policy

Each certificate carries a `policy` object computed from its `not_before`:

- `max_validity_at_issuance_days` - the maximum validity in force at issuance.
- `compliant_at_issuance` - whether the exact lifetime fits that maximum.
- `next_limit_days` and `next_limit_effective` - the next scheduled limit and
  its effective date (empty after the last step).
- `fits_next_limit` - whether the lifetime also fits the next limit.

Certificate validity follows the BR section 6.3.2 history: 1186 days before
2018-03-01, 825 days before 2020-09-01, and 398 days before 2026-03-15, then
200, 100, and 47 days from 2026-03-15, 2027-03-15, and 2029-03-15 (SC-081v3).
Domain validation reuse is 398 days before 2026-03-15, then 200/100/10 days.
`verdict_100d` stays unchanged for compatibility and is a readiness signal,
never a compliance verdict.

A live certificate that does not fit the limit in force at issuance also
produces a `not-compliant-at-issuance` finding, which is in the default failure
policy. A certificate already expired at `--now` is `not_checked` and does not
produce this blocking finding.

## Findings

Findings are deterministic and sorted. The kinds are:

- `matched` - both issued in CT and presented live.
- `live_only` - presented by a probed host but absent from CT; the detail is
  marked `private_or_untrusted` when the chain did not verify. Fails by default.
- `unknown` - the CT record carries neither a fingerprint nor a serial number,
  so it cannot be correlated with anything. This is decided before the deferral
  rule below, so such a record is `unknown` even when it is expired.
- `not_checked` - the comparison was deferred: the certificate already expired,
  no in-scope name was probed, or a relevant name was not observed live as
  served by that host (unprobed, over the cap, a wildcard, or a failed probe).
- `ct_only` - still valid in CT, and every in-scope name is a host that was
  probed and answered live without presenting this certificate. A name seen only
  as a SAN on another host's certificate was never probed, so it makes the
  certificate `not_checked`, never `ct_only`. Reported but not failing by
  default.
- `exceeds-100d` - the certificate validity exceeds 100 days; emitted in
  addition to the kind above. Reported but not failing by default.
- `not-compliant-at-issuance` - the lifetime exceeds the maximum validity in
  force at issuance, for a certificate not already expired at the evaluation
  instant. Fails by default.
- `kube_only` - read from Kubernetes and not observed in CT or a live handshake.
- `renew-before-exceeds-lifetime` - a fixed `spec.renewBefore` is at or beyond
  the issued lifetime. Fails by default.
- `renewal-degraded` - renewal health is degraded. Fails by default.
- `renew-before-loop-at-next-limit` - a fixed `spec.renewBefore` reaches the
  next shorter lifetime. Reported only.
- `duration-exceeds-next-limit` - a requested `spec.duration` exceeds the next
  public-CA lifetime. Reported only.
- `manual-renewal-after-limit` - a manual renewal falls after the next CA/B
  step. Reported only.
- `renewal-config-invalid` - a `spec.duration`, `spec.renewBefore`, or
  `spec.renewBeforePercentage` value cert-manager's own validation rejects.
  Reported only.

Never infer: a comparison the evidence cannot settle is `not_checked`, and a
record that cannot be correlated at all is `unknown`.

## Coverage

Every scan reports a `coverage` object so a partial scan never looks clean. It
is always printed, and the table adds a one-line summary after the findings.

- `targets_requested` - explicit and derived targets, including derived
  hosts dropped by the `--max-hosts` cap (they were requested but not checked).
- `targets_probed` - probes that completed successfully.
- `targets_failed` - probes that failed (the same entries as `probe_errors`).
- `names_not_checked` - names in `unresolved` plus the number of `not_checked`
  findings.
- `sources` - one entry per source, always, with `status` `ok`, `partial`,
  `failed`, or `not_requested` and a non-empty `detail`. A chosen fallback source
  that an earlier source made unnecessary is `not_requested` with detail
  `not needed: earlier source answered`; it is neither failed nor partial.
- `ratio` - `targets_probed / targets_requested` rounded to four decimals, and
  `1.0` when nothing was requested.

The ratio is deliberately about probe coverage, not certificate compliance;
with a positive `--min-coverage`, source health also gates target-less scans so
the `1.0` empty ratio never turns a missing check into a pass.

## Exit codes

The order is **2 usage > 4 all sources unavailable > 3 blocking finding > 5
incomplete scan > 0**. `4` only when at least one external source (Certificate
Transparency or Kubernetes) was requested and every requested one was
unavailable; a failed TLS probe is a `probe_errors` entry, never exit 4, and
partial failures are warnings. `3` when a finding of a kind selected by
`--fail-on` is present. `5` when `--strict` or `--min-coverage` is not met and
nothing else applies. When `4` or `3` wins, `SCD-0020` is still emitted as a
warning so an incomplete scan is not hidden. `2` on usage errors. See
[exit codes](../exit-codes.md).

## Output

JSON follows [`scadenza.scan/v1`](../schema/scan-v1.schema.json) and contains
`certificates`, `findings`, `unresolved`, `probe_errors`, `diagnostics`, and
`coverage`. The table prints the certificates (with `MODE` and `HEALTH`), the
findings summary, a `RISKS` summary when any certificate has a risk, and the
one-line coverage summary. CSV emits one row per (certificate, observation) and
reuses the `scadenza ct` formula-injection escaping (a leading single quote for
cells starting with `=`, `+`, `-`, `@`, tab, or carriage return).

The certificate object gains `correlation_method`, `policy`, and `renewal`
(`mode`, `health`, `evidence`, `risks`). The document gains `coverage` and the
top-level `owners` workload summary, `findings.kind` gains
`not-compliant-at-issuance` and the six renewal risk kinds, and the certificate
table gains `MODE` and `HEALTH` columns plus a `RISKS` summary at the end, all
within `scadenza.scan/v1` under the rules of
[ADR 0007](../adr/0007-json-compatibility.md). It also carries the M3 additions:
`owners`, the per-observation `kubernetes` object, and the Kubernetes
`sources_used`, `verdict_100d`, findings kind, and observation source values.


