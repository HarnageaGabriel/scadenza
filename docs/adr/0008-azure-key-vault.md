# ADR 0008: read-only Azure Key Vault certificate inventory

Status: accepted

## Decision

The Azure source uses the official Azure SDK `azcertificates` v1.5.0 client with the default Azure credential chain. It exposes only list certificate properties, get certificate policy, and get certificate operations behind a consumer-owned interface. It never reads Key Vault secrets or keys.

The public `cer` bytes from get certificate are parsed and hashed with SHA-256 for inventory correlation. Key Vault's `x5t` is SHA-1, so it is not used as a fingerprint. The CER contains the public certificate, not its private key.

Authentication is `azidentity.NewDefaultAzureCredential`. This supports local Azure CLI login and deployment identities without secret-bearing flags or another credential configuration surface.

## Consequences

Stored certificates correlate with CT and live TLS observations by SHA-256. Policy reads add renewal evidence. Bounded concurrency, request rate limiting, and safe structured errors keep the source predictable. Certificate metadata permissions are required; secret and key permissions are neither required nor used.
