# Ownership

A certificate inventory is only actionable when it says who owns each
certificate. scadenza never guesses that. An owner is reported only when an
explicit rule names it, and every owner carries the rule that produced it, so
the answer is auditable.

## Sources

An owner value is read from, in this order:

- `label` - a label key listed in the ownership file, read from the Secret or
  Certificate object. The default Kubernetes scan obtains Secret labels through
  `PartialObjectMetadata`; it does not read Secret data.
- `annotation` - the same keys, read from the object's annotations.
- `namespace-label` / `namespace-annotation` - the same keys, read from the
  namespace that holds the object. A namespace annotation is always reported as
  `namespace-annotation`, never as `namespace-label`.
- `mapping-file` - a `domains` entry whose domain suffix matches one of the
  certificate names, or a `namespaces` entry for the object's namespace.

Discovery order does not imply precedence: every matching rule contributes an
owner. Owners are sorted and de-duplicated, and each keeps its `owner_source`
and `location`. If no rule matches, the owner list is empty. `owner: ""` means
"no rule matched", never "the owner is unknown but probably X".

`app.kubernetes.io/managed-by` is deliberately **not** consulted. It names the
tooling that manages an object, not the team accountable for its certificate,
and it is a common default that would produce a misleading owner for every
cert-manager object.

## File format

`--ownership-file` takes a YAML file with three optional keys. Unknown keys are
rejected, so a typo cannot silently disable ownership.

```yaml
# Keys read from labels, annotations, and namespaces. Defaults to
# scadenza.io/owner when omitted.
labelKeys:
  - scadenza.io/owner
  - platform.example.com/team

# Domain suffix to owner. The longest matching suffix wins.
domains:
  example.com: team-web
  payments.example.com: team-pay

# Namespace name to owner.
namespaces:
  payments: team-pay
  platform: team-platform
```

Domain matching is case-insensitive and ignores a leading `*.`. For a
certificate with names `api.payments.example.com` and `payments.example.com`,
the longer `payments.example.com` rule wins over `example.com`.
Domain and namespace keys that normalize to the same value are rejected, so
their owner cannot depend on YAML map iteration order.

## Example

Given this Secret:

```yaml
metadata:
  name: api-tls
  namespace: payments
  labels:
    scadenza.io/owner: team-pay
```

and a `payments` namespace labelled `scadenza.io/owner: team-pay`, the
certificate is reported with `owner: team-pay`,
`owner_source: namespace-label`, `location: namespace/payments`, and a second
entry for the object label. Both sources are recorded; scadenza does not
silently pick one.

This result does not require `--kube-secrets`: Secret metadata and namespace
metadata contain every signal used above. The opt-in affects certificate bytes
and fingerprint correlation, not label or annotation ownership.

## Diagnostics

An unreadable or malformed ownership file is `SCD-0019` and a usage error:
scadenza refuses to run with a broken ownership file rather than silently
reporting no owners. See [diagnostics](diagnostics/SCD-0019.md).
