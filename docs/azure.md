# Azure Key Vault source

`scadenza scan --azure-keyvault https://NAME.vault.azure.net` reads certificate metadata, policy, and the public CER from Azure Key Vault. The flag is repeatable. The adapter uses the official Azure SDK `azcertificates` v1.5.0 client, with authentication from `azidentity.NewDefaultAzureCredential` (environment, workload or managed identity, and Azure CLI login). The credential is created lazily, and no secret or token is accepted as a flag.

The source performs only certificate list, get-certificate, and get-policy requests. It never calls secret or key endpoints. Key Vault exposes a certificate's private key through the secret endpoint of the same name, so scadenza deliberately cannot use that endpoint. The `x5t` field is SHA-1 and is not used; scadenza computes SHA-256 over the public certificate DER returned in `cer`.

```sh
scadenza scan --azure-keyvault https://prod.vault.azure.net
scadenza scan --azure-keyvault https://one.vault.azure.net --azure-keyvault https://two.vault.azure.net --azure-qps 5
```

The default rate is five requests per second. Reads use bounded concurrency, honor cancellation, and stream list pagination. Vault failures are isolated: other vaults are still read, and coverage is partial when at least one vault succeeds. A 401 fails that vault; a 403 while listing also leaves that vault unread, while a 403 on an individual certificate or policy read skips only that certificate. Other item failures, including a certificate deleted after listing or one without an issued CER, emit SCD-0033 and make coverage partial. Cancellation fails the whole Azure source and discards its certificates. Diagnostics contain only HTTP status, when available, and vault host.

## Permissions

For Azure RBAC, use the built-in **Key Vault Reader** role at the narrowest vault scope. Microsoft documents it as metadata-only, without secret-value access. For legacy access policies, grant only certificate `get` and `list`. Never grant a secrets role for scadenza.

**VERIFY:** the role and data actions were checked against Microsoft's [certificate access control](https://learn.microsoft.com/azure/key-vault/certificates/certificate-access-control) and [built-in role](https://learn.microsoft.com/azure/role-based-access-control/built-in-roles/security#key-vault-reader) pages on 2026-10-15; re-check before provisioning because built-in definitions can change.

Tags feed the configured ownership label keys and a match has `owner_source: tag`. Observations also include vault host, name, version, enabled state, validity, SANs, issuer, policy validity in months, lifetime actions, tags, and content type.
