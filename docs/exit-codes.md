# Exit codes

`scadenza` uses stable process exit codes so scripts can distinguish findings from operational failures.

| Code | Meaning |
| ---: | --- |
| 0 | Command completed successfully; for `scadenza scan`, no `ct_only`, `live_only`, or `exceeds-100d` finding is present. |
| 1 | An unexpected internal error occurred. |
| 2 | Command-line usage or input was invalid. |
| 3 | Findings are present: at least one `ct_only`, `live_only`, or `exceeds-100d` finding was reported by `scadenza scan`. |
| 4 | Every requested source was unavailable (`scadenza ct`, `scadenza scan`). `scadenza scan` exits 4 only when at least one external source (Certificate Transparency or Kubernetes) was requested and every requested one failed (a failed TLS probe is a `probe_errors` entry, not exit 4). Kubernetes is unavailable after a 401 or when no requested Secret or Certificate list succeeds; a 403 is partial when another requested list succeeds. A partial source failure, or an unavailable Kubernetes source while Certificate Transparency answered, is a warning rather than exit 4. |
