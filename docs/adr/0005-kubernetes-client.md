# ADR 0005: Read Kubernetes and cert-manager read-only with client-go

Status: accepted

## Context

M3 adds a Kubernetes input source to `scadenza scan`. It must read
`kubernetes.io/tls` Secrets and cert-manager `Certificate`, `Issuer`, and
`ClusterIssuer` resources, correlate them with Certificate Transparency and live
handshakes by SHA-256 fingerprint, and never modify a cluster or touch private
keys.

There are two access paths. The typed `k8s.io/client-go` clients understand core
objects, but nothing outside the Kubernetes API groups. cert-manager publishes
its own Go module (`github.com/cert-manager/cert-manager`) with typed APIs, but
its module documentation states that, unlike the API versions themselves, the
Go module carries no compatibility guarantee. Importing it would couple
scadenza's build to an upstream module whose API may change between releases.

## Decision

- Read core `Secret` and `Namespace` objects with the typed client from
  `k8s.io/client-go`.
- Read cert-manager `certificates`, `issuers`, and `clusterissuers` with the
  dynamic client and `unstructured` objects under `cert-manager.io/v1`. The
  issuer type is derived from which documented `spec` key exists (`acme`, `ca`,
  `selfSigned`, `vault`, `venafi`); anything else, including an issuer in a
  different API group, is reported as `external` or `unknown`, never guessed. An
  unrecognized field therefore degrades to `unknown` instead of failing.
- Do not import the cert-manager Go module. Only the documented, versioned CRD
  surface is read.
- Use read-only verbs only: `list` and `get`. No `watch`, `create`, `update`,
  `patch`, or `delete` is ever issued. The shipped ClusterRole grants exactly
  these verbs, see `deploy/rbac/scadenza-readonly.yaml`.
- Request TLS Secrets with the server-side field selector
  `type=kubernetes.io/tls` and paginate with `limit`/`continue`, so a large
  cluster is streamed instead of buffered.
- Read only `tls.crt`. The `tls.key` value is dropped from the object
  immediately after the list response is decoded, before parsing, logging, or
  retention. No code path decodes, copies, hashes, or prints it, and tests
  assert the key bytes never appear in any output or error, including for a
  malformed secret. cert-manager `spec.*.privateKeySecretRef` is read as a name
  only; the referenced Secret is never fetched.
- Limit of this guarantee: the Kubernetes API returns the whole Secret object, so `tls.key` still travels over the wire to the scanner process and exists in memory until it is dropped. RBAC cannot exclude a single data key. Run scadenza only against clusters and from hosts you trust, and prefer per-namespace Roles (see `deploy/rbac/`).
- Configure client-go rate limits: `--kube-qps` (default 5) with client-go's
  default burst, so a scan cannot flood an API server.
- Load configuration with `clientcmd` from `--kubeconfig`, `KUBECONFIG`, the
  in-cluster service account, or `--kube-context`. Credentials, kubeconfig
  content, and raw Kubernetes client error strings are never printed; errors
  expose only status, StatusReason, resource kind, and namespace.
- Ownership is never inferred from certificate data or from cert-manager specs.
  It comes only from labels, annotations, namespaces, and an explicit mapping
  file (see `docs/ownership.md`).

## Consequences

- New direct modules: `k8s.io/client-go`, `k8s.io/apimachinery`, and
  `k8s.io/api`, pinned together at `v0.37.0`. This is the justification required
  by ADR 0002. They add a larger transitive graph (`k8s.io/klog/v2`,
  transport, discovery, and auth helpers), which increases supply-chain surface
  and binary size. VERIFY: the release binary size delta has not been measured
  in this environment; record the before/after of `go build -trimpath` for the
  release that first ships M3.
- A missing cert-manager installation is expected. The dynamic client reports
  the missing CRDs as an informational diagnostic (`SCD-0018`), not an error,
  and TLS Secrets are still reported.
- The Kubernetes source stays read-only, and the e2e cluster grants only the
  documented verbs, so any accidental write would fail loudly in CI.

## Addendum: M5a Secret access default

ADR 0006 decision 8 changes the Secret path before the M3 behavior ships. The
default `scan --kube` now uses client-go's metadata client and
`PartialObjectMetadata` to observe TLS Secret names, namespaces, labels, and
annotations without receiving `data`. Certificate facts come from cert-manager
`Certificate` spec/status and have no fingerprint. They remain unresolved
unless exactly one CT or live certificate has the same complete normalized name
set and exact `notAfter`, in which case the weak correlation is recorded as
`names_and_expiry`.

The original typed Secret list is retained only behind `--kube-secrets` (or
`kube.secrets: true`). That opt-in emits `SCD-0028`, reads `tls.crt`, and keeps
the immediate `tls.key` removal described above. The default RBAC manifest no
longer grants any Secret access; a separate opt-in manifest grants Secret
`list`/`get` cluster-wide and documents a per-namespace Role alternative.

Kubernetes authorization treats collection GET as `list`, and the official
authorization documentation warns that `get`, `list`, and `watch` can return
full resource details and are equivalent for access to returned data. RBAC
therefore cannot distinguish a `PartialObjectMetadata` list from a full Secret
list. A default service account without a Secrets rule receives 403 for the
metadata request; scadenza reports `SCD-0015` and continues with its other
Kubernetes reads.
