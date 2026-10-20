# Exit codes

`scadenza` uses stable process exit codes so scripts can distinguish findings from operational failures.

When more than one condition holds, the highest-priority code wins. The order is
**2 (usage) > 4 (all sources unavailable) > 3 (blocking finding) > 5 (incomplete scan) > 0**.

| Code | Meaning |
| ---: | --- |
| 0 | Command completed successfully. For `scadenza scan`, no finding of a kind selected by `--fail-on` is present. |
| 1 | An unexpected internal error occurred. |
| 2 | Command-line usage, input, `--fail-on`, `--min-coverage`, `--now`, or `--config` was invalid (`SCD-0001`, `SCD-0021`, `SCD-0022`). |
| 3 | A blocking finding is present: at least one reported finding has a kind selected by `--fail-on`. `scadenza ct` never exits 3. |
| 4 | Every requested external source was unavailable (`scadenza ct`, `scadenza scan`). `scadenza scan` exits 4 only when at least one external source (Certificate Transparency, Kubernetes, or Azure Key Vault) was requested and every requested one failed (a failed TLS probe is a `probe_errors` entry, not exit 4). Kubernetes is unavailable after a 401 or when no requested Secret or Certificate list succeeds; a 403 is partial when another requested list succeeds. Azure Key Vault is unavailable when the credential chain fails or when no vault could be read at all; a vault that answered while another one failed is a partial source. A partial source failure, or an unavailable source while another requested source answered, is a warning rather than exit 4. |
| 5 | The scan was incomplete: `--strict` found a partial or failed source, a failed probe, or an unchecked name, or `--min-coverage` was not met (`SCD-0020`). |

## Precedence

- **2 first.** Usage and input errors are detected before any scan work, so a bad
  invocation never reports a scan result.
- **4 before 3.** When every requested external source is unavailable, any
  finding would be an artifact of missing data, so an operational failure is
  reported rather than a verdict.
- **3 before 5.** A blocking finding keeps the pre-0.1.0 meaning of exit 3 for
  CI. `--strict` and `--min-coverage` only decide the exit code when nothing
  else is wrong; they never hide a finding. When exit 4 or exit 3 wins, the incomplete
condition is still emitted as warning-severity `SCD-0020`.
- **5 before 0.** An otherwise clean scan that did not check everything it was
  asked to check still exits non-zero.

## Failure policy

`--fail-on` selects which finding kinds cause exit 3. The default is
`live_only,not-compliant-at-issuance,renew-before-exceeds-lifetime,renewal-degraded`.
`ct_only` is deliberately excluded (CDNs issue several certificates in parallel,
so it is noisy), `exceeds-100d` stays a readiness signal rather than a
compliance failure, and the three remaining renewal kinds
(`renew-before-loop-at-next-limit`, `duration-exceeds-next-limit`,
`manual-renewal-after-limit`) are reported but do not fail by default. `none`
disables exit 3. Every finding is still reported in the output; only the exit
code changes.

## `scadenza ct`

`scadenza ct` exits `0` on success, `2` on a usage or input error, and `4` when
every selected source failed.
