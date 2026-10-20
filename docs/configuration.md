# Configuration

`scadenza scan` can read an optional YAML configuration file. The file is
**never auto-loaded**: nothing is read unless `--config path` is given, so the
same invocation always reads the same inputs.

```yaml
version: 1

# Domains to query in Certificate Transparency and to probe.
domains:
  - example.com

# Explicit hosts to probe. `host:port` is allowed; `port` supplies the default.
hosts:
  - www.example.com
  - api.example.com:8443

# One host per line; blank lines and everything after `#` is ignored.
hostsFile: hosts.txt

# Derive probe hosts from non-wildcard CT names (default true).
fromCT: true

# Default probe port (default 443).
port: 443

kube:
  # Read the Kubernetes source. Every other key in this block requires it: a
  # file that sets one of them while enabled is false is a usage error.
  enabled: true
  # Read tls.crt from TLS Secrets. Off by default; requires enabled: true.
  # Emits SCD-0029 naming the namespaces whose Secret data may be read.
  secrets: false
  context: kind-scadenza
  namespaces:
    - payments
  ownershipFile: ownership.yaml

azure:
  # Read-only certificate inventory; repeatable as --azure-keyvault.
  keyVaults:
    - https://prod.vault.azure.net

# Declared renewal modes, per domain. The only accepted value is `manual`: it is
# positive evidence for renewal classification. An automatic mechanism (a
# cert-manager Certificate or annotated TLS Secret) still wins. Keys are
# normalized with the shared domain normalizer (lowercase, no leading wildcard,
# no trailing dot), so `*.Example.COM.` and `example.com` are the same key. See
# renewal.md.
renewal:
  example.com: manual

policy:
  # Finding kinds that cause exit 3. One of ct_only, live_only, exceeds-100d,
  # not-compliant-at-issuance, renew-before-exceeds-lifetime, renewal-degraded,
  # renew-before-loop-at-next-limit, duration-exceeds-next-limit,
  # manual-renewal-after-limit, renewal-config-invalid,
  # keyvault-validity-exceeds-next-limit,
  # keyvault-renew-trigger-exceeds-lifetime, or none alone. Default:
  # [live_only, not-compliant-at-issuance, renew-before-exceeds-lifetime,
  # renewal-degraded].
  failOn:
    - live_only
    - not-compliant-at-issuance
    - renew-before-exceeds-lifetime
    - renewal-degraded
  # Exit 5 when any source is partial or failed, any probe failed, or any item
  # was not checked.
  strict: false
  # Exit 5 when the coverage ratio is below this percentage (0-100).
  minCoverage: 0
```

Relative `hostsFile` and `kube.ownershipFile` paths are resolved against the
directory containing the configuration file, not the process working directory.
Absolute paths are used unchanged. Paths are used as given: a relative path is
resolved against the configuration file's directory, and a path may point
anywhere the user can read.

## Precedence

Command-line flags always win over the file. A value is taken from the file only
when the matching flag was not set on the command line; otherwise the flag value
is used. The mapping is one flag per key: `--domain`/`domains`,
`--host`/`hosts`, `--hosts-file`/`hostsFile`, `--from-ct`/`fromCT`,
`--port`/`port`, `--kube`/`kube.enabled`, `--kube-secrets`/`kube.secrets`,
`--kube-context`/`kube.context`,
`--namespace`/`kube.namespaces`, `--ownership-file`/`kube.ownershipFile`,
`--azure-keyvault`/`azure.keyVaults`,
`--fail-on`/`policy.failOn`, `--strict`/`policy.strict`,
`--min-coverage`/`policy.minCoverage`. There is no flag for `renewal`; it is
only read from the file.

## Validation

Decoding is strict. An unreadable file, an unknown key, a missing or wrong
`version` (must be `1`), an out-of-range `port` or `minCoverage`, an empty or
unknown `policy.failOn` list, a `renewal` key that is not a valid domain, a
`renewal` value other than `manual`, or `none` combined with another kind is a
usage error (exit 2). Unknown keys and bad values are reported as `SCD-0022`; a
bad `failOn` kind is reported as `SCD-0021`.

The same combination is checked after the file is merged with the command line:
`kube.secrets`, `kube.context`, `kube.namespaces`, or `kube.ownershipFile` set
while the Kubernetes source is off is a usage error (exit 2, `SCD-0001`), the
same as the matching flags without `--kube`.

The file must be a regular file and is read under a 1 MiB cap, so a directory,
a named pipe, a device, or an oversized file is a usage error (exit 2) instead
of a hang. The file must hold exactly one YAML document, and the document may
not nest deeper than 64 levels.
