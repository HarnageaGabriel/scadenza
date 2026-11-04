# Azure Pipelines

**scadenza 0.1.0 is not released yet.** This pipeline installs the tool from a
pinned commit; the release archive block at the end applies once 0.1.0 exists.
The job scans a domain, publishes the JSON report as a pipeline artifact, and
fails on the exit codes that matter. See [CI guides](README.md).

```yaml
# azure-pipelines.yml
trigger:
  - main

pool:
  vmImage: ubuntu-latest

variables:
  # Pin a commit until 0.1.0 is released. Move it forward on purpose.
  SCADENZA_COMMIT: 4ea3e622a8494b0a63334c7db87cc87c31d51fb0
  SCADENZA_DOMAIN: example.com

steps:
  - task: GoTool@0
    inputs:
      version: '1.26.10'
  - script: |
      set -euo pipefail
      go install github.com/HarnageaGabriel/scadenza/cmd/scadenza@"$SCADENZA_COMMIT"
      rc=0
      scadenza scan --domain "$SCADENZA_DOMAIN" --format json \
        --fail-on live_only,not-compliant-at-issuance \
        --strict --min-coverage 90 > scadenza.json || rc=$?
      case "$rc" in
        0) echo "scadenza: no blocking finding" ;;
        3) echo "scadenza: a selected finding is present" ; exit 1 ;;
        4) echo "scadenza: every source was unavailable" ; exit 1 ;;
        5) echo "scadenza: the scan was incomplete" ; exit 1 ;;
        *) echo "scadenza: exit $rc" ; exit 1 ;;
      esac
    displayName: scadenza scan
  - task: PublishPipelineArtifact@1
    inputs:
      targetPath: scadenza.json
      artifactName: scadenza-results
    condition: always()
```

- `GoTool@0` installs the Go toolchain. The version must match the one in
  `go.mod` (1.26.10), and `go install` writes the binary to
  `$(go env GOPATH)/bin`, which the agent puts on `PATH`.
- The report is stdout, so `> scadenza.json` keeps it. Warnings and
  diagnostics go to stderr and stay in the log.
- `|| rc=$?` keeps the step from stopping before the artifact is published,
  and `condition: always()` publishes it even when the scan step failed.

## Secrets

The Cert Spotter key is optional. Add it as a secret variable named
`SCADENZA_CERTSPOTTER_KEY`; the agent exports it to the step environment.

## Exit codes

| Exit code | Meaning |
| ---: | --- |
| 0 | Clean result. |
| 1 | Internal error. |
| 2 | Invalid input. |
| 3 | A finding selected by `--fail-on` is present. |
| 4 | All requested sources unavailable. |
| 5 | Incomplete scan. |

Every code except 0 fails the step; see [exit codes](../exit-codes.md).

## Scanning Azure Key Vault

The Azure source reads certificate metadata, the policy and the public
certificate from Azure Key Vault. It is read-only and never reads the secret
endpoint. See [Azure Key Vault](../azure.md).

Use a service connection of type workload identity federation, so the pipeline
holds no client secret: the agent gets a short-lived token for the service
principal. The `AzureCLI@2` task signs in with that connection, and scadenza
picks the identity up from `azidentity.NewDefaultAzureCredential`, whose chain
ends in the Azure CLI credential when the CLI is signed in.

```yaml
steps:
  - task: AzureCLI@2
    inputs:
      azureSubscription: scadenza-keyvault
      scriptType: bash
      scriptLocation: inlineScript
      addSpnToEnvironment: true
      inlineScript: |
        set -euo pipefail
        go install github.com/HarnageaGabriel/scadenza/cmd/scadenza@"$SCADENZA_COMMIT"
        scadenza scan --domain "$SCADENZA_DOMAIN" \
          --azure-keyvault https://prod.vault.azure.net \
          --format json --strict --min-coverage 90 > scadenza.json
    displayName: scadenza scan with Key Vault
```

The service principal needs read access to the vault only:

- the built-in **Key Vault Reader** role at the narrowest vault scope, or
- for legacy access policies, the certificate `get` and `list` permissions.

Never grant secret or key permissions for scadenza: the source calls only the
certificate list, get-certificate and get-policy endpoints.

The token is short-lived and scadenza never prints it. A vault that rejects the
request is reported as `SCD-0030` (unauthorized), `SCD-0031` (forbidden),
`SCD-0032` (unreachable) or `SCD-0033` (one certificate skipped).

## When 0.1.0 exists

This step replaces the `go install` line. It verifies the release archive with
`scripts/verify-release.sh`, which checks the cosign signature over
`checksums.txt`, the archive checksum, the SBOM and the build provenance, and
needs `curl`, `sha256sum`, `cosign`, `jq` and `gh` on the agent.

```yaml
  - script: |
      set -euo pipefail
      git clone --depth 1 --branch v0.1.0 https://github.com/HarnageaGabriel/scadenza.git scadenza-src
      scadenza-src/scripts/verify-release.sh v0.1.0 --dir /tmp/scadenza-release
      install -m 0755 /tmp/scadenza-release/extract/scadenza /usr/local/bin/scadenza
      scadenza version
    displayName: install scadenza 0.1.0
```

**VERIFY:** the Azure Pipelines syntax used above (`GoTool@0`, `AzureCLI@2`
with `addSpnToEnvironment`, `PublishPipelineArtifact@1`, `condition: always()`
and secret variables) was written from the Microsoft Learn pages "Go tool
task", "AzureCLI task", "PublishPipelineArtifact@1 task" and "Variables and
secrets" without checking them online. The name of the service connection
type and of the federated token the agent exports are not confirmed either.
The Azure SDK side is confirmed against the `azidentity` v1.15.0 source.
