# Threat model

scadenza is a read-only inventory tool. It talks to the network and to
clusters, it parses data from parties it does not control, and it is often run
with powerful credentials. Every destination it can reach, and the bound on
each request, is listed in [docs/network.md](network.md). This page states what
it protects, what it trusts, and how each risk is limited. Report weaknesses
through [SECURITY.md](../SECURITY.md).

## Assets

- **Credentials** the user gives it: kubeconfig and tokens, Azure identity,
  the optional Cert Spotter API key.
- **Secret material** it could encounter: Kubernetes `tls.key`, Key Vault private
  keys.
- **The user's network position**: scans start from the user's machine or CI
  runner.
- **Integrity of the result**: a wrong "all clear" is a security failure.
- **Integrity of the release**: the binary people download.

## Trust boundaries

| Source | Trust | Why it matters |
| --- | --- | --- |
| Certificate Transparency search APIs (Cert Spotter, crt.sh) | Untrusted data | Any CA can log anything for any name; a malicious or compromised service can return crafted records. |
| TLS servers being probed | Untrusted | They choose the certificate, the chain and the timing. Nothing they present is trusted, only recorded. |
| Kubernetes and cloud APIs | Trusted for what they return about the user's own estate, untrusted as input to parsers | Objects can hold hostile or malformed values. |
| Configuration, ownership and hosts files | Trusted as intent, parsed strictly | Unknown keys are errors. |
| Dependencies and GitHub Actions | Supply chain | Pinned and checked in CI. |

## Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Private keys or tokens leak into output | `tls.key` is dropped before parsing and never read. The Key Vault source reads certificates as public CER only and never calls the secret or key endpoints: `internal/azurekv` exposes only list, get-certificate and get-policy. Key Vault diagnostics carry only the HTTP status and the vault host. Errors are structured (status, reason, resource), never raw client text. Tests plant fake keys and tokens and assert they never appear in any stream. |
| Reading more than needed | Only `list` and `get` verbs. Kubernetes reads Secret metadata only by default; Secret data needs the explicit `--kube-secrets` flag and a separate RBAC manifest. Key Vault needs only certificate `get` and `list` permissions (see [docs/azure.md](azure.md)). Minimal manifests in `deploy/rbac/`. |
| Scanning what the user did not name | Only named domains and hosts, plus host names found in Certificate Transparency under a named domain. No IP ranges. Wildcard names are never probed. `--max-hosts` caps the derived set, and capped hosts are reported as not checked. A host name that came from Certificate Transparency is resolved and checked before it is dialed: a host that resolves only to a loopback, link-local, multicast, or unspecified address is never dialed and is reported as a `blocked-address` probe failure. The hosts an operator names are not restricted, and the RFC 1918 ranges are still probed, so an internal estate stays scannable. |
| An unbounded Certificate Transparency answer | A query collects at most 50000 entries. A result that stops at the cap marks the source partial in the coverage summary and raises `SCD-0034`, so a truncated answer never looks complete. |
| A hostile TLS server | The handshake never sends application data; certificate verification is run separately against the system roots and the result is recorded, not acted on. Timeouts, concurrency limits and response size caps apply. |
| Hostile or malformed input | Strict parsers with fuzz targets (CT decoders, PEM chains, host and domain parsing, configuration and ownership files). Bounded response bodies and pagination. A Certificate Transparency name is validated with the same host name parser that validates the names an operator types: a name that fails it is never probed, and it is reported as not checked instead of being dropped. |
| Credential forwarding | HTTP redirects to another host or scheme are refused and `Authorization` is never forwarded. Credentials are accepted from the environment or the cloud credential chain, never as flags. TLS verification is always on for API calls. |
| A partial scan that looks clean | Coverage is reported, `--strict` and `--min-coverage` fail incomplete scans, and unchecked names are `not_checked`, never silently dropped (see [exit codes](exit-codes.md)). |
| CSV or terminal injection from untrusted names | A diagnostic line on stderr starts with the diagnostic code, then the severity in brackets, then the summary and the detail, so untrusted text is never at the start of a line. Untrusted text is sanitized everywhere it is displayed: control and format characters (including bidirectional overrides and zero width characters) are removed, tabs and line breaks become a single space, and the text is capped (512 characters for a diagnostic detail, 256 characters for a table or CSV cell). A CSV cell never contains a line break, and a cell that starts with a formula character is neutralised. |
| Compromised release | Releases are built by GitHub Actions from a tag, checksummed, signed with keyless cosign and attested; actions are pinned to full commit SHAs; releases start as drafts. See [docs/release.md](release.md). |
| Vulnerable dependency | `govulncheck`, Dependabot, CodeQL and OpenSSF Scorecard run in CI. The vulnerability scan builds with the Go version pinned in `go.mod`, the same toolchain the releases are built with. |

## Out of scope

- A compromised machine or CI runner running scadenza: whoever controls it
  already holds the credentials.
- Attacks on the CA/Browser Forum rules or on Certificate Transparency itself.
- Confidentiality of the *names* of your certificates: they are public by
  design once logged.
- Active exploitation of the probed servers. scadenza only completes a TLS
  handshake.

## Assumptions to keep true

- RBAC cannot distinguish a metadata list of Secrets from a full list, so
  granting `list` on `secrets` grants access to the data. Use the manifest
  without a `secrets` rule unless you need `--kube-secrets`.
- A Kubernetes API response for Secrets contains `tls.key` on the wire. scadenza
  discards it immediately, but the bytes reach the process. Run it only from
  hosts you trust.
