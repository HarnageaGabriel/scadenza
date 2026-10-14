# ADR 0004: Read live certificate chains without trusting the connection

Status: accepted

## Context

M2 correlates Certificate Transparency issuances with what hosts actually
present. To do that it must read chains served by endpoints that are expired,
self-signed, incomplete, or simply misconfigured. Refusing those endpoints would
hide exactly the certificates the product exists to report, but connecting to
them must never make scadenza trust, or act on, anything the peer sends.

## Decision

`internal/tlsprobe` dials the host, performs a TLS handshake with
`InsecureSkipVerify` set to true, records the presented chain, and closes the
connection immediately. It never sends application data, never reuses the
connection, and never reads key material.

Reading the chain and deciding trust are separate steps. A `VerifyPeerCertificate`
hook captures the leaf fingerprint (SHA-256 of the DER, lowercase hex), serial,
subject names, issuer, validity window, negotiated TLS version, and whether the
chain contained more than the leaf. The same hook then performs a real
`x509.Certificate.Verify` against the system roots (or an injected pool) for the
probed name and stores `trusted: bool` plus the verification error text. Nothing
presented by a probed server is trusted implicitly; every failure class is
recorded (`dns`, `connect-timeout`, `refused`, `tls-alert`, `no-certificate`,
`handshake-failed`).

The `gosec` G402 exception is scoped to the single `InsecureSkipVerify`
assignment in `internal/tlsprobe/tlsprobe.go` and carries a pointer to this ADR.
No other file weakens verification. Network access is injectable through a
`Dialer` interface so tests can run against in-process TLS servers.

## Dependencies

ADR 0002 requires a written rationale for new third-party modules and accepts it
"here or in a later ADR". M2 introduces the milestone that ADR 0002 anticipated:
bounded concurrent I/O. It adds `golang.org/x/sync/errgroup` for
`SetLimit`-bounded parallel probes. Certificate parsing, verification, and the
handshake itself use only the standard library (`crypto/tls`, `crypto/x509`,
`crypto/sha256`). No other module is added.

## Consequences

- Expired, self-signed, name-mismatched, and private-PKI certificates are still
  reported, but always with `trusted: false` and a verification error.
- A failed probe is a recorded finding input, never a reason to trust or skip.
- Operationally, the binary performs outbound TCP to explicitly named hosts
  only; no IP-range scanning, no DNS enumeration beyond resolving probed host
  names.
- VERIFY: Go reports chain-building failures (for example an unknown authority
  or an incomplete chain) before validity errors, so `verify_error` may name the
  authority rather than the expiry. The boolean `trusted` is unaffected.