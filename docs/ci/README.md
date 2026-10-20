# CI guides

scadenza exits with stable codes, so a pipeline can gate on the result. There
is one guide per CI system:

| Guide | CI system |
| --- | --- |
| [GitHub Actions](github-actions.md) | GitHub Actions, scheduled or on demand |
| [GitLab CI](gitlab-ci.md) | GitLab CI/CD, one job in `.gitlab-ci.yml` |
| [Azure Pipelines](azure-pipelines.md) | Azure Pipelines, one stage, plus a Key Vault section |

Everything below this table applies to any CI system, including the three
above.

## Exit codes

| Code | Meaning | What the pipeline should do |
| ---: | --- | --- |
| 0 | The scan finished and no selected finding is present. | Pass the job. |
| 1 | An unexpected internal error. | Fail the job and report a bug. |
| 2 | The command line or the input was invalid. | Fail the job and fix the command. |
| 3 | A finding selected by `--fail-on` is present. | Fail the job: the policy was broken. |
| 4 | Every requested source was unavailable. | Fail the job: nothing was checked. |
| 5 | The scan was incomplete (`--strict` or `--min-coverage` not met). | Fail the job. |
| 130 | The run was stopped by a signal. | Fail the job: the scan was cancelled, not clean. |

The precedence is 130 > 2 > 4 > 3 > 5 > 0. The full rules are in
[exit codes](../exit-codes.md).

Only 0 is a pass. 3 and 5 are policy results; 1, 2, 4 and 130 are operational
failures, and a pipeline that collected no data must not be green. If a
Certificate Transparency outage must not block a merge, allow 4 explicitly and
keep 3 and 5 blocking.

A CI system that cancels a job sends `SIGTERM`: scadenza stops the scan, writes
no report, and exits 130.

## Recommended strictness

```sh
scadenza scan --domain example.com --format json \
  --fail-on live_only,not-compliant-at-issuance \
  --strict --min-coverage 90
```

- `--strict` exits 5 when a source is partial or failed, a probe failed, or an
  item was not checked.
- `--min-coverage 90` exits 5 when fewer than 90 percent of the requested
  targets were probed. With a positive threshold, a scan without targets also
  fails when a requested source is not `ok`.
- `--fail-on` chooses the finding kinds that cause exit 3. The default is
  `live_only,not-compliant-at-issuance,renew-before-exceeds-lifetime,renewal-degraded`.
  `--fail-on none` turns exit 3 off; keep `--strict` and `--min-coverage` on.

`--min-coverage` measures probe coverage, not compliance. Every report
carries a `coverage` object, so a partial scan never looks clean.

## Keep credentials out of the log

- Put every secret in the secret store of the CI system: a masked and
  protected CI/CD variable in GitLab, a secret variable in Azure Pipelines, a
  repository secret in GitHub Actions. Never in the YAML file and never in the
  command line.
- scadenza reads credentials from the environment only. It never accepts a
  token, a password or a key as a flag, and it never prints one.
- The only credential it reads is the optional Cert Spotter key in
  `SCADENZA_CERTSPOTTER_KEY`. It is sent as a Bearer authorization header.
  Without it the unauthenticated Cert Spotter quota applies.
- Do not enable shell tracing (`set -x`) around the scan and do not print the
  environment.
- For Azure Key Vault, prefer workload identity federation: the pipeline hands
  over a short-lived token and nothing is stored. See
  [Azure Pipelines](azure-pipelines.md).

## Pin the version

scadenza 0.1.0 is not released yet. Until it is, install the module pinned to
a commit, never to a branch:

```sh
go install github.com/HarnageaGabriel/scadenza/cmd/scadenza@4ea3e622a8494b0a63334c7db87cc87c31d51fb0
```

Replace the commit with the `main` commit you want to trust, and move it
forward deliberately. The module declares Go 1.26.9, so the build image must
provide it or let the Go toolchain download it (`GOTOOLCHAIN=auto`, the
default). `@main` in an automated pipeline installs whatever the branch points
to at run time.

When 0.1.0 exists, install the release archive and verify it with
`scripts/verify-release.sh v0.1.0` instead; see [install](../install.md) and
the release block in [GitLab CI](gitlab-ci.md) and
[Azure Pipelines](azure-pipelines.md).
