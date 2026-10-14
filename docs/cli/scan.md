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
`spec.renewBefore`, `status.notAfter`, `status.renewalTime`, and the `Ready`
condition. These raw facts are stored now so that M5 can classify renewal
without re-reading the cluster. Private keys and `privateKeySecretRef` targets
are never read.

Kubernetes certificates that do not verify against the system roots keep the
inventory entry but get no 100-day verdict: `verdict_100d` is `not_applicable`
and `public` stays `null` (unknown). A certificate seen only in Kubernetes is
reported with the finding kind `kube_only`.

Owners come only from labels, annotations, namespaces, and an optional mapping
file; see [ownership](../ownership.md). Each owner records its source in the
`owners` array (`owner`, `owner_source`, `location`).

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

The live certificate is verified separately against the system roots (see
[ADR 0004](../adr/0004-tls-verification-policy.md)); `public` is `true`, `false`,
or `null` (unknown for CT-only certificates). `exceeds` is computed from the
exact, unrounded validity duration, as in `scadenza ct`.

## Findings

Findings are deterministic and sorted. The kinds are:

- `matched` - both issued in CT and presented live.
- `live_only` - presented by a probed host but absent from CT; the detail is
  marked `private_or_untrusted` when the chain did not verify.
- `unknown` - the CT record carries neither a fingerprint nor a serial number,
  so it cannot be correlated with anything. This is decided before the deferral
  rule below, so such a record is `unknown` even when it is expired.
- `not_checked` - the comparison was deferred: the certificate already expired,
  no in-scope name was probed, or a relevant name was not observed live as
  served by that host (unprobed, over the cap, a wildcard, or a failed probe).
- `ct_only` - still valid in CT, and every in-scope name is a host that was
  probed and answered live without presenting this certificate. A name seen only
  as a SAN on another host's certificate was never probed, so it makes the
  certificate `not_checked`, never `ct_only`.
- `exceeds-100d` - the certificate validity exceeds 100 days; emitted in
  addition to the kind above.
- `kube_only` - read from Kubernetes and not observed in CT or a live handshake.

Never infer: a comparison the evidence cannot settle is `not_checked`, and a
record that cannot be correlated at all is `unknown`.

## Exit codes

`0` when no `ct_only`, `live_only`, or `exceeds-100d` finding exists (matched,
`not_checked`, and `kube_only` findings do not affect the exit status). `3` when
one of those findings exists. `4` only when at least one external source
(Certificate Transparency or Kubernetes) was requested and every requested one
was unavailable; a failed TLS probe is a `probe_errors` entry, never exit 4, and
partial failures are warnings. `2` on usage errors. See
[exit codes](../exit-codes.md).

## Output

JSON follows [`scadenza.scan/v1`](../schema/scan-v1.schema.json) and contains
`certificates`, `findings`, `unresolved`, `probe_errors`, and `diagnostics`.
The table prints the certificates followed by a findings summary. CSV emits one
row per (certificate, observation) and reuses the `scadenza ct` formula-injection
escaping (a leading single quote for cells starting with `=`, `+`, `-`, `@`, tab,
or carriage return).

The certificate object additively gains `owners` (when an ownership rule
matched) and each observation gains a `kubernetes` object for Kubernetes
sources. `sources_used`, `verdict_100d`, `findings.kind`, and the observation
`source` enum gained the Kubernetes values without bumping `scadenza.scan/v1`.
