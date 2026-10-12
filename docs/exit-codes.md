# Exit codes

`scadenza` uses stable process exit codes so scripts can distinguish findings from operational failures.

| Code | Meaning |
| ---: | --- |
| 0 | Command completed successfully. |
| 1 | An unexpected internal error occurred. |
| 2 | Command-line usage or input was invalid. |
| 3 | Findings are present; reserved for a later milestone. |
| 4 | A required external source was unavailable. |
