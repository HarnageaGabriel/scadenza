# Renewal classification

`scadenza scan` answers two questions about every certificate it finds: **how is
it renewed** (`renewal_mode`) and **is that renewal working** (`renewal_health`).
Both always carry the evidence they are based on, and configurations that will
break under shorter lifetimes are reported as findings. This is ADR 0006,
decisions 5 and 6.

Missing evidence is `unknown`, never a guess. scadenza never infers renewal from
a certificate name or issuer unless a documented, explicit fact says so.

## The two fields

`renewal_mode` is one of:

- `automatic` - a managing controller renews the certificate.
- `manual` - an operator declared that they renew it by hand.
- `unknown` - no renewal mechanism could be established.

`renewal_health` is one of:

- `healthy` - a controller reports `Ready=True` and both `status.renewalTime`
  and `status.notAfter` are in the future.
- `degraded` - `Ready=False`, `status.renewalTime` passed more than one hour
  before the evaluation instant, or `status.notAfter` has passed.
- `configured` - an automatic mechanism is present but no operational signal
  confirms it works.
- `unknown` - there is no automatic mechanism, or no evidence at all.

Health describes an automatic mechanism. A manual renewal has no mechanism
scadenza can observe, so its health is `unknown`; the risk
`manual-renewal-after-limit` reports the workload instead.

## Rules, with their sources

### Automatic

- A cert-manager `Certificate` whose `spec.issuerRef` resolves to an `acme`,
  `ca`, `selfSigned`, `vault`, or `venafi` issuer is `automatic`. The
  `Certificate` resource is the renewal mechanism itself, so cert-manager drives
  renewal: <https://cert-manager.io/docs/usage/certificate/>.
- A `Certificate` whose `issuerRef` points at a foreign API group (`external`)
  or cannot be resolved (`unknown`) is still `automatic`, because cert-manager
  still owns the renewal loop. Its health is capped at `configured`, because
  nothing operational can be confirmed.
- A `kubernetes.io/tls` Secret carrying the
  `cert-manager.io/certificate-name` annotation is `automatic` and `configured`
  even when the `Certificate` resource was not read (for example a missing CRD).
  The annotation is already read for ownership; renewal reuses it.

### Unknown

- A certificate seen only in Certificate Transparency or a live TLS handshake,
  or a `kubernetes.io/tls` Secret with no `cert-manager.io/certificate-name`
  annotation and no `Certificate` referencing it, is `unknown`, **not**
  `manual`. The evidence carries the fact `no-managing-controller-found`.

### Manual

`manual` requires positive evidence. Today the only source is an explicit
declaration in `scadenza.yaml`:

```yaml
version: 1
renewal:
  example.com: manual
```

The declaration is recorded as evidence with source `config`. An automatic
mechanism still wins: a `manual` declaration for a certificate that a
cert-manager `Certificate` manages does not change the mode, and the
declaration stays visible as evidence. Later, Azure Key Vault
EmailContacts-only policies (M5) will be the second positive source.

## Health, from the injected clock

The evaluation instant comes from `--now` (or the current time). A cert-manager
`Certificate` is `healthy` when `Ready=True` and both `status.renewalTime` and
`status.notAfter` are in the future. It is `degraded` when `Ready=False` (the
`reason` is recorded), when `status.renewalTime` passed more than one hour
before the instant, or when `status.notAfter` has passed. When the status
carries no signal at all it is `configured`.

## Certificate Transparency cadence is evidence, never a classification

For each certificate's name set, scadenza computes from the Certificate
Transparency records it already fetched:

- `ct-issuances-365d` - the number of issuances in the last 365 days.
- `ct-median-interval-days` - the median interval in days between consecutive
  issuances (rounded to the nearest whole day), when there are at least two.

These facts explain the observed cadence. They never decide `renewal_mode` or
`renewal_health`.

The window is a fixed `365 * 24h` ending at the evaluation instant, so a leap
year cannot stretch it to 366 days, and a record whose `notBefore` is after the
evaluation instant is ignored. Records are deduplicated by stable issuance
identity before the cadence is computed: the precertificate and the final
certificate of one issuance share an issuer and serial, so they count once, and
the duplicate records that overlapping domain queries return count once too.

## Risks: configurations that break under shorter lifetimes

Each risk is also a finding, with its own diagnostic:

- `renew-before-exceeds-lifetime` (`SCD-0023`) - a fixed `spec.renewBefore` is
  at or beyond the actual issued lifetime, so cert-manager renews in a loop now.
- `renew-before-loop-at-next-limit` (`SCD-0024`) - a fixed `spec.renewBefore`
  reaches the next CA/B maximum validity, or, for an ACME issuer on
  `acme-v02.api.letsencrypt.org`, the next announced Let's Encrypt lifetime. The
  `effective` date is recorded. `spec.renewBeforePercentage` is recommended
  because it follows the actual issued duration.
- `duration-exceeds-next-limit` (`SCD-0025`) - a requested `spec.duration`
  exceeds the CA/B maximum validity that governs the next issuance for an ACME
  issuer on a known public CA. When `spec.duration` is absent, cert-manager's
  documented 90-day default is used and recorded as the evidence fact
  `duration-source=default`. The known ACME directory hosts are Let's Encrypt
  (`acme-v02.api.letsencrypt.org`), ZeroSSL (`acme.zerossl.com`), Google Trust
  Services (`dv.acme-v02.api.pki.goog`, `pki.goog`), and Buypass
  (`api.buypass.com`). An unknown ACME server produces no finding, only evidence.
- `renewal-degraded` (`SCD-0026`) - `renewal_health` is `degraded`.
- `manual-renewal-after-limit` (`SCD-0027`) - a manual certificate's `notAfter`
  falls after the next CA/B step, so the manual workload grows.
- `renewal-config-invalid` (`SCD-0028`) - `spec.duration`, `spec.renewBefore`,
  or `spec.renewBeforePercentage` holds a value cert-manager's own validation
  rejects: `spec.duration` must be at least 1h, the effective `spec.renewBefore`
  must be at least 5m, `spec.duration` must be greater than `spec.renewBefore`
  (equal is invalid), and `spec.renewBeforePercentage` must be an integer
  percentage between 1 and 99 of the actual issued lifetime. Source:
  <https://cert-manager.io/docs/usage/certificate/>.

The CA/B step these risks compare against is chosen at the evaluation instant
(`--now`), not from the certificate's `notBefore`: the next scheduled step, or,
when no further step remains, the step already in force. A step that already
took effect is therefore never reported with a stale effective date.

`renew-before-exceeds-lifetime` and `renewal-degraded` are on by default in
`--fail-on`; the others are reported but do not fail the run.

## Per-owner workload

The scan document carries a top-level `owners` summary. Each entry reports the
certificate count per owner, how many are `automatic`, `manual`, `unknown`, or
`degraded`, and the manual renewal workload per year at the 200, 100, and 47-day
CA/B maximum validity. Manual renewals per year are `ceil(365 / max_validity)`
per manual certificate: 2 at 200 days, 4 at 100 days, and 8 at 47 days.
Certificates with no declared owner are grouped under `(unowned)`. The summary
is sorted deterministically.

`--group-by owner|names|none` (default `none`) only groups the table rows; JSON
is unchanged.

## Time rules and sources

The dated validity limits come from `internal/policy` (CA/Browser Forum
SC-081v3). Renewal-specific facts come from:

- cert-manager, `spec.duration`, `spec.renewBefore`, `spec.renewBeforePercentage`,
  `status.renewalTime`, and the `Ready` condition:
  <https://cert-manager.io/docs/usage/certificate/>.
  Default `spec.duration` is 90 days, the default renewal is at 2/3 of the
  actual issued duration, `spec.duration` must be greater than
  `spec.renewBefore`, and `spec.renewBeforePercentage` is a percentage of the
  actual issued lifetime.
- Let's Encrypt, `https://letsencrypt.org/2025/12/02/from-90-to-45`: the default
  profile is 90 days, 64 days from 2027-02-10, and 45 days from 2028-02-16.
  Let's Encrypt recommends renewing at about two-thirds of the lifetime or with
  ARI, not at a fixed interval.

**VERIFY:** the 64-day (2027-02-10) and 45-day (2028-02-16) Let's Encrypt step
dates are encoded from the announcement and must be confirmed against the
official post before they are relied on. Because they are announced rather than
confirmed, a risk detail names them as announced, not confirmed. The public ACME
directory hosts and the CA/B backdating allowance carry the same `VERIFY`
markers in the code.

scadenza reads only fields it already reads from the cluster: `spec.duration`,
`spec.renewBefore`, `spec.renewBeforePercentage`, `status.notAfter`,
`status.renewalTime`, the `Ready` condition, the issuer type and ACME server,
and the Secret annotation. An explicit `spec.renewBefore` is treated as fixed;
`spec.renewBeforePercentage` is computed from the actual issued lifetime.
