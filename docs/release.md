# Release runbook

1. Bump the version where the project defines it and update `CHANGELOG.md`.
2. Run the CI gates locally: `go build ./...`, `go vet ./...`, `go test -race ./...`, and `make cover-floors`.
3. Create and push an annotated tag, for example `git tag -a v0.1.0 -m v0.1.0` and `git push origin v0.1.0`.
4. Inspect the draft GitHub Release and its generated notes and assets.
5. Verify the checksum signature with `cosign verify-blob --bundle checksums.txt.bundle checksums.txt` using the repository's expected certificate identity and OIDC issuer. VERIFY: confirm the exact identity and issuer before publishing.
6. Verify each artifact with `sha256sum --check checksums.txt` (or the platform equivalent).
7. Verify provenance with `gh attestation verify <artifact> --repo HarnageaGabriel/scadenza`.
8. Publish the reviewed draft in GitHub Releases.
9. Post-release: install from the release, verify `scadenza --version`, check provenance and checksums again, and announce the release.

The Homebrew block is intentionally commented until the tap and token secret
are provisioned. Do not put tokens in this repository.
