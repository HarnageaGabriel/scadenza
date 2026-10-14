# ADR 0002: Keep the M0 dependency set small

Status: accepted

## Decision

M0 uses Cobra for conventional CLI parsing, `gopkg.in/yaml.v3` for the embedded diagnostic registry, and `go-cmp` in tests for readable structural diffs. The standard library covers all other M0 behavior.

`golang.org/x/sync` is intentionally deferred until a milestone introduces bounded concurrent I/O; carrying an unused module would add supply-chain surface without behavior.

M3 adds `k8s.io/client-go`, `k8s.io/apimachinery`, and `k8s.io/api` so `scadenza scan --kube` can read Kubernetes and cert-manager objects read-only. The justification for that dependency set, including why cert-manager's own Go module is not imported, is [ADR 0005](0005-kubernetes-client.md).
M1 adds `golang.org/x/net/idna` to normalize internationalized domain names according to the maintained Go IDNA profile. Reimplementing IDNA safely is outside the product's scope; all HTTP, retry, rate-limit, and rendering behavior remains in the standard library.

## Consequences

The binary performs no network access and includes no telemetry. New third-party modules require a short justification here or in a later ADR.
