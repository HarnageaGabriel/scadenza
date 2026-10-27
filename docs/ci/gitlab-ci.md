# GitLab CI

**scadenza 0.1.0 is not released yet.** This job installs the tool from a
pinned commit. The release archive block at the end applies once 0.1.0 exists.

The job scans a domain, keeps the JSON report as an artifact, and fails the
pipeline on the exit codes that matter.

```yaml
# .gitlab-ci.yml
stages:
  - scan

variables:
  # Pin a commit until 0.1.0 is released. Move it forward deliberately.
  SCADENZA_COMMIT: 4ea3e622a8494b0a63334c7db87cc87c31d51fb0
  SCADENZA_DOMAIN: example.com

default:
  image: golang:1.26

scadenza-scan:
  stage: scan
  script:
    - go install github.com/HarnageaGabriel/scadenza/cmd/scadenza@"$SCADENZA_COMMIT"
    - |
      rc=0
      scadenza scan --domain "$SCADENZA_DOMAIN" --format json \
        --fail-on live_only,not-compliant-at-issuance \
        --strict --min-coverage 90 > scadenza.json || rc=$?
      case "$rc" in
        0) echo "scadenza: no blocking finding" ;;
        3) echo "scadenza: a selected finding is present" ; exit 1 ;;
        4) echo "scadenza: every requested source was unavailable" ; exit 1 ;;
        5) echo "scadenza: the scan was incomplete" ; exit 1 ;;
        *) echo "scadenza: exit $rc" ; exit 1 ;;
      esac
  artifacts:
    when: always
    paths:
      - scadenza.json
    expire_in: 1 week
```

What the job does:

- `go install` writes the binary to `/go/bin`, which is on `PATH` in the
  `golang` image.
- The report is stdout, so `> scadenza.json` keeps it as the artifact.
  Warnings and diagnostics go to stderr and stay in the job log.
- `|| rc=$?` keeps the shell from stopping before the artifact is uploaded.
- `artifacts: when: always` uploads the report even when the job fails.

Replace `example.com` with your domain. The image must provide the Go
version declared in `go.mod` (1.26.10).

## Secrets

The Cert Spotter key is optional. Store it as a masked and protected CI/CD
variable named `SCADENZA_CERTSPOTTER_KEY`; GitLab exports it to the job
environment and scadenza reads it from there. Do not put the value in
`.gitlab-ci.yml`. Without the key the unauthenticated Cert Spotter quota
applies.

## Exit codes

| Exit code | Meaning | Job result |
| ---: | --- | --- |
| 0 | Clean result. | Pass. |
| 1 | Internal error. | Fail. |
| 2 | Invalid input. | Fail. |
| 3 | A finding selected by `--fail-on` is present. | Fail. |
| 4 | All requested sources unavailable. | Fail. |
| 5 | Incomplete scan. | Fail. |

See [exit codes](../exit-codes.md) for the precedence and the full rules, and
[CI guides](README.md) for the parts that every CI system shares.

## When 0.1.0 exists

This block replaces the `go install` line. It verifies the release archive
before using it; the script needs `curl`, `sha256sum`, `cosign`, `jq` and
`gh`, and the image must provide them.

```yaml
    - |
      set -euo pipefail
      git clone --depth 1 --branch v0.1.0 https://github.com/HarnageaGabriel/scadenza.git scadenza-src
      scadenza-src/scripts/verify-release.sh v0.1.0 --dir /tmp/scadenza-release
      install -m 0755 /tmp/scadenza-release/extract/scadenza /usr/local/bin/scadenza
      scadenza version
```

`verify-release.sh` checks the cosign signature over `checksums.txt`, the
archive checksum, the SBOM and the build provenance, and runs the extracted
binary. See [install](../install.md).

**VERIFY:** the GitLab keywords used above (`stages`, `default:image`,
`script` with a block scalar, `artifacts` with `when: always`, `expire_in` and
CI/CD variables) were written from GitLab's "Keyword reference for
.gitlab-ci.yml", "Store job artifacts" and "CI/CD variables" pages without
checking them online, and the `golang:1.26` image tag was not checked against
Docker Hub. Confirm them before the first run.
