# Exit codes

`scadenza` uses stable process exit codes so scripts can distinguish findings from operational failures.

| Code | Meaning |
| ---: | --- |
| 0 | Command completed successfully; for `scadenza scan`, no `ct_only`, `live_only`, or `exceeds-100d` finding is present. |
| 1 | An unexpected internal error occurred. |
| 2 | Command-line usage or input was invalid. |
| 3 | Findings are present: at least one `ct_only`, `live_only`, or `exceeds-100d` finding was reported by `scadenza scan`. |
| 4 | Every selected external source was unavailable (`scadenza ct`, `scadenza scan`). |
