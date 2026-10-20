# Azure Key Vault source

`scadenza scan --azure-keyvault https://NAME.vault.azure.net` reads certificate metadata, policy, and the public CER from Azure Key Vault. The flag is repeatable. The adapter uses the official Azure SDK `azcertificates` v1.5.0 client, with authentication from `azidentity.NewDefaultAzureCredential`; the exact credential chain is listed under [Credential chain](#credential-chain). The credential is created lazily, and no secret or token is accepted as a flag.

The source performs only certificate list, get-certificate, and get-policy requests. It never calls secret or key endpoints. Key Vault exposes a certificate's private key through the secret endpoint of the same name, so scadenza deliberately cannot use that endpoint. The `x5t` field is SHA-1 and is not used; scadenza computes SHA-256 over the public certificate DER returned in `cer`.

```sh
scadenza scan --azure-keyvault https://prod.vault.azure.net
scadenza scan --azure-keyvault https://one.vault.azure.net --azure-keyvault https://two.vault.azure.net --azure-qps 5
```

The default rate is five requests per second. Reads use bounded concurrency, honor cancellation, and stream list pagination. Every request is bounded by a 30 second per try timeout and at most three retries, so a vault that stops answering fails the vault instead of hanging the scan. Vault failures are isolated: other vaults are still read, and coverage is partial when at least one vault succeeds. A 401 fails that vault; a 403 while listing also leaves that vault unread, while a 403 on an individual certificate or policy read skips only that certificate. Other item failures, including a certificate deleted after listing or one without an issued CER, emit SCD-0033 and make coverage partial. Cancellation fails the whole Azure source and discards its certificates. Diagnostics contain only HTTP status, when available, and vault host.

## Credential chain

`azidentity.NewDefaultAzureCredential` from `azidentity` v1.15.0, the version pinned in `go.mod`, tries these credential sources in this order and stops at the first one that returns a token:

1. `EnvironmentCredential` — a service principal or a user configured from environment variables.
2. `WorkloadIdentityCredential` — the federated token of the Azure workload identity webhook.
3. `ManagedIdentityCredential` — a system-assigned or user-assigned managed identity.
4. `AzureCLICredential` — the `az` CLI login.
5. `AzureDeveloperCLICredential` — the `azd` CLI login.
6. `AzurePowerShellCredential` — the Azure PowerShell module login.

The environment variables that select or limit them:

- `AZURE_TOKEN_CREDENTIALS` narrows the chain. `prod` tries only `EnvironmentCredential`, `WorkloadIdentityCredential`, and `ManagedIdentityCredential`; `dev` tries only `AzureCLICredential`, `AzureDeveloperCLICredential`, and `AzurePowerShellCredential`; any other value must name one credential type from the list above, matched case-insensitively, and selects only that one. A value that is none of these is rejected and the credential fails to build.
- `AZURE_TENANT_ID` and `AZURE_CLIENT_ID` are required by `EnvironmentCredential`. `AZURE_CLIENT_SECRET`, or `AZURE_CLIENT_CERTIFICATE_PATH` with the optional `AZURE_CLIENT_CERTIFICATE_PASSWORD`, or `AZURE_USERNAME` with `AZURE_PASSWORD`, select how it authenticates. `AZURE_CLIENT_SEND_CERTIFICATE_CHAIN` is optional.
- `AZURE_CLIENT_ID`, `AZURE_FEDERATED_TOKEN_FILE`, and `AZURE_TENANT_ID` configure `WorkloadIdentityCredential`.
- `AZURE_CLIENT_ID` selects a user-assigned managed identity for `ManagedIdentityCredential`; without it the system-assigned identity is used.
- `AZURE_AUTHORITY_HOST`, `AZURE_ADDITIONALLY_ALLOWED_TENANTS`, and `AZURE_REGIONAL_AUTHORITY_NAME` apply to the whole chain.

Set `AZURE_TOKEN_CREDENTIALS` in CI to the one credential type the runner should use, so a stray developer login on the runner cannot be used instead. `AzurePipelinesCredential` is not part of the chain in this version and cannot be selected that way.

**VERIFY:** the list, the order, and the environment variables were read from the `azidentity` v1.15.0 source in the Go module cache (`default_azure_credential.go`, `environment_credential.go`, `workload_identity.go`, `azidentity.go`) on 2026-10-20; re-check them when the pinned version changes.

## Permissions

For Azure RBAC, use the built-in **Key Vault Reader** role at the narrowest vault scope. Microsoft documents it as metadata-only, without secret-value access. For legacy access policies, grant only certificate `get` and `list`. Never grant a secrets role for scadenza.

**VERIFY:** the role and data actions were checked against Microsoft's [certificate access control](https://learn.microsoft.com/azure/key-vault/certificates/certificate-access-control) and [built-in role](https://learn.microsoft.com/azure/role-based-access-control/built-in-roles/security#key-vault-reader) pages on 2026-10-15; re-check before provisioning because built-in definitions can change.

Tags feed the configured ownership label keys and a match has `owner_source: tag`. Observations also include vault host, name, version, enabled state, validity, SANs, issuer, policy validity in months, lifetime actions, tags, and content type.
