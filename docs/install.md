# Install and verify scadenza

There is **no tagged release yet**. Until 0.1.0, install from source:

```sh
go install github.com/HarnageaGabriel/scadenza/cmd/scadenza@main
```

`go install` builds from source with your own toolchain and verifies modules
against the Go checksum database. Pin a commit instead of `@main` in anything
you automate.

## Release archives (from 0.1.0)

Each release contains an archive per platform, `checksums.txt`, its signature
bundle `checksums.txt.bundle`, an SBOM per archive, and a build provenance
attestation. Releases start as drafts and are published only after review
([runbook](release.md)).

The example uses version `v0.1.0` on Linux amd64. Change both variables for
another release or platform.

```bash
set -euo pipefail

version=v0.1.0
archive=scadenza_0.1.0_linux_amd64.tar.gz
base=https://github.com/HarnageaGabriel/scadenza/releases/download/$version
curl -fLO "$base/$archive"
curl -fLO "$base/checksums.txt"
curl -fLO "$base/checksums.txt.bundle"

# 1. The checksums file was signed by this repository's release workflow.
cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity "https://github.com/HarnageaGabriel/scadenza/.github/workflows/release.yml@refs/tags/$version" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# 2. The archive matches the signed checksums.
sha256sum --check --ignore-missing checksums.txt

# 3. The archive was built by GitHub Actions from this repository.
gh attestation verify "$archive" --repo HarnageaGabriel/scadenza
```

VERIFY: the exact file names, the certificate identity and the bundle format
before the first release; this page is written ahead of it and must be
re-checked against the draft release.

Never run a binary whose signature or checksum does not verify.
