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
  enabled: false
  context: kind-scadenza
  namespaces:
    - payments
  ownershipFile: ownership.yaml

policy:
  # Finding kinds that cause exit 3. One of ct_only, live_only, exceeds-100d,
  # not-compliant-at-issuance, or none alone. Default:
  # [live_only, not-compliant-at-issuance].
  failOn:
    - live_only
    - not-compliant-at-issuance
  # Exit 5 when any source is partial or failed, any probe failed, or any item
  # was not checked.
  strict: false
  # Exit 5 when the coverage ratio is below this percentage (0-100).
  minCoverage: 0
```

## Precedence

Command-line flags always win over the file. A value is taken from the file only
when the matching flag was not set on the command line; otherwise the flag value
is used. The mapping is one flag per key: `--domain`/`domains`,
`--host`/`hosts`, `--hosts-file`/`hostsFile`, `--from-ct`/`fromCT`,
`--port`/`port`, `--kube`/`kube.enabled`, `--kube-context`/`kube.context`,
`--namespace`/`kube.namespaces`, `--ownership-file`/`kube.ownershipFile`,
`--fail-on`/`policy.failOn`, `--strict`/`policy.strict`,
`--min-coverage`/`policy.minCoverage`.

## Validation

Decoding is strict. An unreadable file, an unknown key, a missing or wrong
`version` (must be `1`), an out-of-range `port` or `minCoverage`, an unknown
`policy.failOn` kind, or `none` combined with another kind is a usage error
(exit 2). Unknown keys and bad values are reported as `SCD-0022`; a bad
`failOn` kind is reported as `SCD-0021`.