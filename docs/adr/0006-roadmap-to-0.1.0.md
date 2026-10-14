# ADR 0006: Roadmap to 0.1.0

Status: accepted (2026-10-14)

## Context

M0 to M3 are done: `ct`, `scan` with TLS probes, and the Kubernetes and
cert-manager source. Two reviews of the plan were run: one internal, and one
external review based on the public documentation. They agree on the main
point. scadenza still does not answer its own question, "will this renewal
keep up with the new pace?". They also agree that a scan which checked only
part of the inventory must not look like a clean result.

## Decisions

1. **Reliability before renewal classification, and both before Azure Key
   Vault.** The next milestones are M4a (reliable results), M4b (renewal
   classification), M5 (safe Kubernetes defaults and Azure Key Vault), then M6
   (0.1.0).
2. **Coverage, compliance and source health are reported separately.** "No
   finding" must never read as "everything checked". The JSON gains a
   `coverage` section. `--strict` fails on any partial failure or unchecked
   item, and `--min-coverage <pct>` fails below a threshold.
3. **Configurable failure policy.** `--fail-on` chooses which findings fail the
   run. By default `ct_only` is reported but does not fail it: CDNs issue
   several certificates in parallel, so `ct_only` is noisy. Exit code 3 keeps
   meaning "a blocking finding is present".
4. **Time rules are dated.** A policy table encodes the
   200 / 100 / 47-day maximum validity and the domain validation reuse periods
   by effective date. `--now` fixes the evaluation instant, so the same input
   gives the same output and you can evaluate against a future date.
   `verdict_100d` stays as a readiness signal and is never presented as
   compliance.
5. **Renewal is two fields, always with evidence.** `renewal_mode` is
   `automatic`, `manual` or `unknown`. `renewal_health` is `configured`,
   `healthy`, `degraded` or `unknown`. Each value carries the evidence it is
   based on (`Ready` condition, `renewalTime`, issuer type, `duration` and
   `renewBefore`, Key Vault lifetime actions). Missing evidence gives
   `unknown`, never a guess. The issuance cadence observed in Certificate
   Transparency is shown as evidence, never as the classification.
6. **Automatic does not mean ready.** Configurations that will break under
   short lifetimes are findings: a fixed `renewBefore` too close to the
   duration, a `duration` over 100 days with a public issuer, or a Key Vault
   validity above the maximum. Let's Encrypt moves to 64-day certificates on
   2027-02-10 and to 45-day certificates on 2028-02-16, and recommends renewing
   at about two-thirds of the lifetime (VERIFY against letsencrypt.org before
   encoding).
7. **Correlation states its strength.** Every certificate carries a
   `correlation_method` of `sha256`, `issuer_serial` or `unresolved`.
8. **Kubernetes without Secrets by default.** `--kube` reads only cert-manager
   resources, namespaces and Secret metadata. Reading Secret data to compute
   fingerprints requires an explicit `--kube-secrets`. The RBAC examples are
   split the same way. This changes unreleased behavior, which is acceptable
   before 0.1.0.
9. **JSON compatibility rules before 0.1.0.** A later ADR defines what may
   change within `scan/v1`. Contract tests validate every scenario against the
   published schema and diff schemas between releases.
10. **Ownership provenance is exact.** `owner_source` gains
    `namespace-annotation`. Namespace annotations are no longer reported as
    `namespace-label`.

## Milestones

- **M4a, reliable results:** decisions 2, 3, 4, 7, 9 and 10, plus a small
  `scadenza.yaml` holding domains, hosts, ownership and the failure policy.
- **M4b, renewal classification:** decisions 5 and 6, grouping by owner and by
  name set, and manual-renewal workload per owner at 200, 100 and 47 days.
- **M5, Kubernetes and cloud:** decision 8, optional probing of every address
  of a host, and Azure Key Vault.
- **M6, 0.1.0:** GoReleaser, Homebrew, checksums, CI examples, a DCO check, a
  nightly fuzzing workflow, and a decision on krew.
- **After 0.1.0:** snapshot diff, SARIF if a sensible mapping exists, and
  renewal history.

## Consequences

The core answer ships in M4b, well before the February 2027 target, even if
Azure Key Vault slips. Every finding stays explainable from recorded evidence.
