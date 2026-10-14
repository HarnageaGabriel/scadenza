# Security policy

## Supported versions

During pre-alpha development, only the latest commit on `main` receives
security fixes. Published support windows will be documented before the first
stable release.

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** for this repository:
<https://github.com/HarnageaGabriel/scadenza/security/advisories/new>. Do not
open a public issue or disclose details before a coordinated release. Include
affected versions, impact, reproduction steps, and any proposed mitigation.

We target acknowledgement within 3 business days, initial triage within 7
calendar days, and a remediation plan within 14 calendar days. Severity,
complexity, and coordinated-disclosure needs can change the release date. We
will credit reporters unless they request anonymity.

The project follows coordinated vulnerability disclosure. These targets are
project goals, not a warranty or a statement that a particular legal role
applies to the project.

## What counts as a vulnerability

scadenza reads clusters, cloud accounts and network endpoints with credentials
you provide, so these classes are in scope and treated as high severity:

- A secret leaves its source: a private key, token, kubeconfig content, API key
  or cloud credential appears in output, logs, diagnostics, artifacts or error
  text.
- A command writes where it promises to be read-only, or asks for more
  permission than documented (see `deploy/rbac/`).
- A scan reaches hosts or address ranges the user did not name (the scope rule
  in [docs/threat-model.md](docs/threat-model.md)).
- A crafted input (a Certificate Transparency response, a certificate, a TLS
  server, a Kubernetes object, a configuration or ownership file) crashes the
  tool, exhausts memory, or makes it request attacker-chosen URLs.
- A release artifact, workflow or dependency weakens the integrity of what you
  download (unsigned or unverifiable binaries, unpinned actions).

Ordinary bugs, wrong classifications and false findings are not vulnerabilities:
please open a normal issue.

## Verifying releases

Releases are built in GitHub Actions and are meant to be verifiable. The steps
are in [docs/install.md](docs/install.md) and [docs/release.md](docs/release.md).

## Safe harbor

We will not pursue good-faith security research that follows this policy, stays
within your own systems or test infrastructure, avoids privacy violations and
service disruption, and reports promptly and privately.
