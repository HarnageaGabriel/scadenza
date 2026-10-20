# Network destinations

scadenza is read-only, but it is not offline. Two commands open connections:
`scadenza ct` and `scadenza scan`. `scadenza version` opens none.

This page lists every destination the program can contact, where that
destination comes from, and what bounds each request. Every row names the file
and function that builds the client. Claims about the Azure and Kubernetes
libraries were read from the pinned module source in the Go module cache; a
claim marked **VERIFY** was not confirmed there.

The threat model this page supports is in [threat-model.md](threat-model.md).
That page states what scadenza protects and what it trusts; this page is the
inventory of the connections it can make and of the bound on each one.

## Destinations

| Destination | When it is contacted | Who chooses it | Protocol and port | What is sent | Protections | Source |
| --- | --- | --- | --- | --- | --- | --- |
| Cert Spotter API, `api.certspotter.com` | `ct <domain>`; `scan` with `--domain` and `--from-ct` (on by default). First default source. | Fixed in the code. The user picks whether to use it (`--source`). | HTTPS, 443 | `GET /v1/issuances` with `domain`, `include_subdomains`, `match_wildcards=true`, `expand=dns_names,issuer` and an `after` cursor. `User-Agent: scadenza/<version>`. `Authorization: Bearer <key>` when `SCADENZA_CERTSPOTTER_KEY` is set. | 45 s request timeout; 10 s connect; 10 s TLS handshake; 20 s response-header timeout; 32 MiB body cap; one request per second; three attempts, plus one more after HTTP 429 with `Retry-After` clamped to 30 s; 1000 page cap; 50 000 entry cap, and a `scan` query that stops there is reported as a partial source and writes `SCD-0034`; at most 10 redirects and only to the same scheme and host, with `Authorization` deleted on every redirect; proxy variables honoured; TLS verified against the system roots. | `internal/ct/certspotter.go` (`CertSpotter.fetch`, `CertSpotter.SearchResult`); `internal/httpx/httpx.go` (`New`, `Do`, `CheckRedirect`); `internal/cli/ct.go` (`productionCTDependencies`) |
| crt.sh, `crt.sh` | Same commands. Second default source, used when Cert Spotter fails. | Fixed in the code. | HTTPS, 443 | `GET /` with `q=<domain>` (or `q=%.domain` when subdomains are included) and `output=json`. `User-Agent: scadenza/<version>`. No authorization header. | Same bounds as Cert Spotter, except the request interval is 12 seconds and there is no pagination: one request per query. A result longer than the 50 000-entry cap is cut there, and the source is reported as partial with `SCD-0034`. | `internal/ct/crtsh.go` (`CrtSH.Search`, `CrtSH.SearchResult`); `internal/cli/ct.go` (`productionCTDependencies`) |
| TLS probe target, named by the user | `scan` with `--host`, `--hosts-file`, or `--domain`; the apex of the domain is a named target too. | The user, by name or in a file. `host:port` overrides the port; `--port` sets the default. | TLS handshake over TCP on the target port, 443 by default. No HTTP, no application data. | A TLS ClientHello with the host name as SNI, then the connection is closed. | Per-probe timeout `--timeout` (5 s) covers resolve, connect and handshake; concurrency limit `--concurrency` (8); the presented chain is verified separately against the system roots and the result is recorded, not acted on; handshake verification is off on purpose so expired, self-signed and misconfigured chains can still be read ([adr/0004](adr/0004-tls-verification-policy.md)); proxy variables are **not** honoured, the resolved address is dialed directly. The special-address guard does **not** apply to a named target: a name the user typed that resolves to a loopback, a metadata address or a private address is dialed. A name the user typed is the user intent, so it is never guarded, not even when the same name also appears in Certificate Transparency. | `internal/tlsprobe/tlsprobe.go` (`Prober.Probe`, `handshake`, `capture`, `dialResolved`); `internal/cli/scan.go` (`parseTargets`, `runProbeJobs`, `newScanCommand`) |
| TLS probe target, derived from Certificate Transparency | `scan --domain ...` with `--from-ct` (on by default). | Derived from CT data, which is untrusted, but restricted to names under a domain the user named. `--max-hosts` (200) caps the set. | TLS handshake over TCP, `--port` (443 by default). | A TLS ClientHello with the CT name as SNI. | Same as the row above, except that the special-address guard (`Prober.BlockSpecialAddresses`) **is** enabled for these hosts: `scan` builds a second prober with the guard set and probes every CT-derived host with it, so a name that resolves to `127.0.0.1` or `169.254.169.254` is never dialed. The guard covers the hosts derived from Certificate Transparency names and only those: a host the user named (the `--host` option, the hosts file, or the apex of the `--domain` option) is never guarded, not even when the same name also appears in Certificate Transparency, because a name the user typed is the user intent. The guard refuses loopback, link-local unicast, link-local multicast, interface-local multicast, multicast, the unspecified address, everything in `0.0.0.0/8`, the IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible (`::a.b.c.d`), IPv4-translated (`::ffff:0:0:0/96`), NAT64 (`64:ff9b::/96`) and 6to4 (`2002::/16`) forms, the whole local use NAT64 prefix (`64:ff9b:1::/48`) and the whole Teredo prefix (`2001::/32`), and the cloud metadata endpoints `100.100.100.200`, `168.63.129.16`, `192.0.0.192`, `169.254.170.2` and `fd00:ec2::254`. A host whose addresses are all refused fails with the class `blocked-address`, which is reported in `probe_errors` and as `SCD-0010`. Wildcard names are never probed and are reported as not checked; names outside the named domain are dropped; a name that is not a valid host name is never probed and is listed as unresolved with the reason `invalid-name`. RFC 1918 ranges, the shared address space (`100.64.0.0/10`) and IPv6 unique local addresses are still probed. | `internal/cli/scan.go` (`deriveHosts`, `underAnyDomain`, `runProbeJobs`); `internal/tlsprobe/tlsprobe.go` (`Prober.Probe`, `Prober.BlockSpecialAddresses`, `filterSpecialAddresses`, `specialAddressReason`, `addressReason`, `embeddedIPv4`) |
| Kubernetes API server | `scan --kube`, or `kube.enabled` in the configuration file. | The user, through the kubeconfig: `--kubeconfig`, else `KUBECONFIG`, else `~/.kube/config`; `--kube-context` picks the context; inside a pod the in-cluster service account is used. The host is the cluster `server:` URL, so it is whatever the kubeconfig says. | HTTPS (or HTTP if the kubeconfig says so) on the port in that URL, 443 by default. | `GET` only: `/api/v1/namespaces`; `/api/v1/namespaces/{ns}/secrets?fieldSelector=type=kubernetes.io/tls&limit=500&continue=...`; `/apis/cert-manager.io/v1/namespaces/{ns}/certificates`; `/apis/cert-manager.io/v1/namespaces/{ns}/issuers`; `/apis/cert-manager.io/v1/clusterissuers`. `User-Agent: scadenza/<version>`. The metadata client negotiates only the PartialObjectMetadataList media types, so no Secret data is returned. Authorization comes from the kubeconfig credential. | Read-only verbs, `list` and `get`, never `watch` or a write; 30 s per-request timeout; client-side rate limit `--kube-qps` (5 per second, burst twice that); proxy variables honoured when the kubeconfig sets no proxy; TLS verified unless the kubeconfig sets `insecure-skip-tls-verify`; no credential, kubeconfig content or raw client error is printed. | `internal/kube/config.go` (`restConfig`, `Load`, `newMetadataClient`); `internal/kube/kube.go` (`Scanner.Scan`, `secretMetadata`, `secrets`, `namespaces`, `certificateFacts`); `internal/kube/metadata.go` (`partialObjectMetadataTransport`); `internal/cli/scan.go` (`newScanCommand`) |
| Kubernetes exec credential plugin | `scan --kube` when the kubeconfig user has an `exec` credential entry. | The kubeconfig author. | None from scadenza: this is a local process. client-go runs the configured command with its arguments, resolved through `PATH`, with `KUBERNETES_EXEC_INFO` in the environment. | Nothing over the network from scadenza. The plugin receives the cluster information and returns a token on standard output. | No limit added by scadenza. The plugin's own network use, for example a cloud login, is outside scadenza's control and outside this page. | `internal/kube/config.go` (`restConfig`, which lets clientcmd build the auth provider); `k8s.io/client-go` v0.37.1 `plugin/pkg/client/auth/exec` (`Authenticator.refreshCredsLocked`, `updateCommandAndCheckAllowlistLocked`) |
| Azure Key Vault, the vault host of each `--azure-keyvault` URI | `scan --azure-keyvault https://NAME.vault.azure.net`, repeatable, or `azure.keyVaults` in the configuration file. | The user. The URI must be HTTPS with no path, query, fragment or userinfo; the host is used exactly as given. | HTTPS, 443 | `GET {vault}/certificates?api-version=2025-07-01`; `GET {vault}/certificates/{name}/{version}?api-version=2025-07-01`, where the version is the one in the certificate identifier the list response returned; `GET {vault}/certificates/{name}/policy?api-version=2025-07-01`. `Authorization: Bearer <token>` for the scope `https://vault.azure.net/.default`, taken from the vault's own challenge. `User-Agent: azsdk-go-azcertificates/<version>`. The secret and key endpoints are never called. | 30 s per try with at most three retries; client-side rate limit `--azure-qps` (5 per second); TLS 1.2 minimum and verified against the system roots; proxy variables honoured; pagination follows the `nextLink` URL the vault returns, and Go's HTTP client drops the `Authorization` header on a redirect to another host. | `internal/azurekv/client.go` (`sdkAPI.client`, `sdkAPI.ListCertificateProperties`, `sdkAPI.GetCertificate`, `sdkAPI.GetCertificatePolicy`); `internal/azurekv/source.go` (`ValidateVaultURL`, `Load`, `scanner.Scan`); `internal/cli/scan_azure.go` (`readAzureKeyVault`) |
| Microsoft Entra ID, `login.microsoftonline.com` | `scan --azure-keyvault`, when the default credential chain needs a token from the cloud. | The Azure SDK, from the chain in `docs/azure.md`. The host is the authority host, `AZURE_AUTHORITY_HOST` if it is set. | HTTPS, 443 | `GET https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration`, then `POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` with the client assertion or secret. The scope is the vault's `https://vault.azure.net/.default`. | TLS verified, minimum TLS 1.2; proxy variables honoured. The SDK client sets no overall request timeout, but the token request is made inside the 30 s per-try bound of the vault read that caused it. | `internal/azurekv/client.go` (`newDefaultCredential`); `azidentity` v1.15.0 `default_azure_credential.go` (`NewDefaultAzureCredential`); `azcore` v1.23.3 `cloud/cloud.go` (authority host); `microsoft-authentication-library-for-go` v1.10.1 `apps/internal/oauth/resolvers.go` (`authorityEndpoint.openIDConfigurationEndpoint`) |
| Azure Instance Metadata Service, `169.254.169.254` | `scan --azure-keyvault`, when the managed identity credential is the one that answers. | The platform, not the user. | HTTP, 80 (plain HTTP is the documented IMDS endpoint). | `GET /metadata/identity/oauth2/token` with the `Metadata: true` header and the resource of the vault. On App Service, Cloud Shell or Azure Machine Learning the endpoint is the one in `IDENTITY_ENDPOINT`, `MSI_ENDPOINT` or `IMDS_ENDPOINT` instead. | When the chain holds other credentials the SDK probes the endpoint with a one-second timeout before it gives up on the chain; IMDS failures are retried with backoff, six times at most, one minute per try; proxy variables are honoured. | `azidentity` v1.15.0 `managed_identity_client.go` (`imdsEndpoint`, `newManagedIdentityClient`, `setIMDSRetryOptionDefaults`); `microsoft-authentication-library-for-go` v1.10.1 `apps/managedidentity/managedidentity.go` (`GetSource`, `imdsDefaultEndpoint`) |
| `az`, `azd`, Azure PowerShell | `scan --azure-keyvault`, when one of the developer credentials answers. | The Azure SDK picks the first credential that returns a token. | None from scadenza: these are local processes. | `az account get-access-token -o json --resource <resource>`; `azd auth token -o json --no-prompt`; a PowerShell `Get-AzAccessToken` call. Each returns a token on standard output. The processes themselves may reach the network. | No limit added by scadenza. `AZURE_TOKEN_CREDENTIALS` can restrict the chain to the cloud credentials only. | `azidentity` v1.15.0 `azure_cli_credential.go` (`AzureCLICredential.GetToken`), `azure_developer_cli_credential.go` (`AzureDeveloperCLICredential.GetToken`), `azure_powershell_credential.go` (`AzurePowerShellCredential.GetToken`) |
| The system DNS resolver | Whenever a host name is resolved: every CT query is by name to a fixed host, every TLS probe resolves its target first, and the Kubernetes and Azure clients resolve their API hosts. | The operating system, from its resolver configuration. | UDP or TCP 53 to the resolver the host is configured with. | The name being looked up. | Bounded by the client timeout: 45 s for the HTTP clients, `--timeout` for a probe. A proxy resolves the name instead when one is configured for that client. | `internal/tlsprobe/tlsprobe.go` (`Prober.resolve`); `internal/httpx/httpx.go` (`New`, dialer) |

### Certificate Transparency requests in detail

Both sources are built in `productionCTDependencies`
(`internal/cli/ct.go`): the Cert Spotter client with a one-second interval
limiter, the crt.sh client with a twelve-second interval limiter. The URL is
fixed in the code and cannot be pointed elsewhere; only the order and the
choice of sources are user controlled (`--source`).

Every request carries `User-Agent: scadenza/<version> (+https://github.com/HarnageaGabriel/scadenza)`
(`internal/httpx/httpx.go`, `New`). No cookie, no request body, and nothing
from the local machine is sent. The only credential is the optional Cert Spotter
API key, sent as a bearer token and read from the environment only.

One query collects at most 50 000 entries (`internal/ct/ct.go`, `MaxEntries`).
In `scan`, a source that reaches the cap stops there, is reported as `partial`
in the coverage summary, and writes one `SCD-0034` warning to stderr, so a
truncated answer never looks complete. The `ct` command has its own separate
cap, `--max-results` (1000), and reports it as `SCD-0006`.

### TLS probes in detail

A probe is a TLS handshake and nothing more. The prober resolves the name
once, dials the first address that accepts a connection, completes the
handshake, records the chain, and closes the connection. No application bytes
are sent and the probed server is never trusted: the chain is verified again
afterwards against the system roots, and the verdict is reported rather than
acted on (`internal/tlsprobe/tlsprobe.go`, `capture`).

Two limits shape the target set. Explicitly named targets are never displaced
by `--max-hosts`; names derived from CT are trimmed to that cap and the trimmed
names are reported as not checked. Wildcard names are never probed at all. A
Certificate Transparency name is validated with the same parser that validates
the hosts the user types (`tlsprobe.ParseEndpoint`), so a name that is not a
valid host name never becomes a probe target: it is listed in `unresolved` with
the reason `invalid-name`, its reason text is sanitized, and it counts as a
name that was not checked.

The special-address guard is the defence against a CT name that resolves to an
address inside the machine or the platform metadata service. It is implemented
in `Prober.BlockSpecialAddresses` and it refuses loopback, link-local unicast,
link-local multicast, interface-local multicast, multicast, the unspecified
address and everything in `0.0.0.0/8`, including the IPv4-mapped and
IPv4-compatible IPv6 forms of each.

The IPv6 forms that carry an IPv4 address inside them are unwrapped and the
same rules are applied to the address they carry (`embeddedIPv4`,
`addressReason`): the IPv4-translated prefix `::ffff:0:0:0/96`, whose embedded
address is in the last 32 bits, the NAT64 well-known prefix `64:ff9b::/96`,
whose embedded address is in the last 32 bits too, and the 6to4 prefix
`2002::/16`, whose embedded address is in bits 16 to 47. A NAT64 or 6to4
address that carries a public address is still probed: translating to
`8.8.8.8` is a legitimate target. Two prefixes are refused whole, because the
address they carry cannot be found: the local use NAT64 prefix
`64:ff9b:1::/48`, where the position of the embedded address depends on the
prefix length, and the Teredo prefix `2001::/32`, whose payload is obfuscated.

The cloud metadata endpoints are refused by exact address: `100.100.100.200`
(Alibaba Cloud), `168.63.129.16` (the Azure platform address), `192.0.0.192`
(Oracle Cloud), `169.254.170.2` (already refused as a link-local address) and
`fd00:ec2::254` (AWS IPv6). The ranges around them are not refused: the shared
address space `100.64.0.0/10`, the IPv6 unique local addresses `fc00::/7` and
the RFC 1918 ranges `10.0.0.0/8`, `172.16.0.0/12` and `192.168.0.0/16` are
used by internal estates and tailnets, so they are deliberately still probed,
because an internal estate is a legitimate scan target.

The guard is off by default in the library: `tlsprobe.New` leaves the field
false, and no command-line flag or configuration key sets it. `scan` turns it
on where it matters. `internal/cli/scan.go` builds a second prober, a copy of
the default one with `BlockSpecialAddresses` set, and every host that came
from Certificate Transparency is probed with it, while a host the user named
is probed with the unrestricted prober. The guard therefore covers the hosts
derived from Certificate Transparency names and nothing else. A host the user
named (the `--host` option, the hosts file, or the apex of the `--domain`
option) is never guarded, not even when the same name also appears in
Certificate Transparency: a name the user typed is the user intent. A CT name
that resolves to `127.0.0.1` or `169.254.169.254` is therefore never dialed.
The refusal is an ordinary probe failure with the class `blocked-address`: it
appears in `probe_errors`, it is counted as a failed target, and it is
reported as `SCD-0010`.

### Kubernetes in detail

The client is `client-go` v0.37.1 built from the REST configuration that
`restConfig` (`internal/kube/config.go`) produces. The configuration comes
from `clientcmd`: `--kubeconfig` when given, otherwise the `KUBECONFIG`
environment variable, otherwise `~/.kube/config`; `--kube-context` selects the
context. Inside a pod the in-cluster service account is used instead, which
takes the host from `KUBERNETES_SERVICE_HOST` and `KUBERNETES_SERVICE_PORT`.

The host is therefore the `server:` URL of the selected cluster, on the port in
that URL. Requests carry `User-Agent: scadenza/<version>` and the credential
from the kubeconfig: a bearer token, a client certificate, or an exec plugin.
scadenza never logs the credential, the kubeconfig content, or a raw client
error message.

By default Secret facts come from the metadata client, which asks only for
`PartialObjectMetadataList` and whose `Accept` header is rewritten to the
metadata media types only; a response that is not a `PartialObjectMetadataList`
is rejected (`internal/kube/metadata.go`, `partialObjectMetadataTransport`).
With `--kube-secrets` the typed client is used and the API server returns full
Secret objects, so `tls.key` travels over the wire before scadenza drops it.
Only `list` and `get` are ever issued.

### Azure in detail

The vault host is the host of the `--azure-keyvault` URI, used exactly as
given; `ValidateVaultURL` (`internal/azurekv/source.go`) requires HTTPS and
rejects a path, a query, a fragment or userinfo, and the value is never
trimmed, so the string used for the request and the string shown in a
diagnostic are the same. Requests are certificate list, get-certificate and
get-policy only. The secret and key endpoints of a vault are never called, so
scadenza cannot read a private key.

Authentication uses `azidentity.NewDefaultAzureCredential`
(`internal/azurekv/client.go`, `newDefaultCredential`) with the chain listed in
[azure.md](azure.md). The chain decides which host is contacted:

1. `EnvironmentCredential` and `WorkloadIdentityCredential` reach the Entra ID
   token endpoint at the authority host, `login.microsoftonline.com` by
   default.
2. `ManagedIdentityCredential` reaches the instance metadata service at
   `169.254.169.254`, or the endpoint the platform publishes in
   `IDENTITY_ENDPOINT`, `MSI_ENDPOINT` or `IMDS_ENDPOINT`.
3. `AzureCLICredential`, `AzureDeveloperCLICredential` and
   `AzurePowerShellCredential` run `az`, `azd` or PowerShell locally; those
   processes do their own network work, which scadenza neither controls nor
   records.

The token scope is not fixed by scadenza. The Key Vault client asks the vault
for its authentication challenge and requests a token for the resource the
vault names, which for a public vault is `https://vault.azure.net/.default`.
The SDK then sends the bearer token to the vault host.

**VERIFY:** the exact Entra ID request paths, and the condition under which
the instance metadata service is used, were read from the pinned module source
in the Go module cache (`azidentity` v1.15.0, `azcore` v1.23.3,
`microsoft-authentication-library-for-go` v1.10.1) on 2026-10-20; re-check
them when a pinned version changes. **VERIFY:** the Azure CLI, Azure Developer
CLI and Azure PowerShell commands were read from the same module source; the
network calls those tools make themselves are outside this page.

## Local input files

scadenza reads three local files of its own, and each read is bounded so that
one hostile path can neither hang the process nor exhaust its memory
(`internal/safefile/safefile.go`, `Read`). The path must resolve to a regular
file, so a device, a socket or a named pipe is refused instead of read, and a
file over its cap is an error rather than a truncated read.

| File | Cap | Source |
| --- | --- | --- |
| Configuration file, `--config` | 1 MiB | `internal/config/config.go` (`MaxFileBytes`) |
| Ownership mapping file, `--ownership-file` | 1 MiB | `internal/cli/scan.go` (`maxOwnershipFileBytes`) |
| Hosts file, `--hosts-file` | 4 MiB, and at most 10000 hosts | `internal/cli/scan.go` (`maxHostsFileBytes`, `MaxHostsEntries`) |

The hosts file is the only one of the three whose contents are read as
network targets: every host it declares is probed. The configuration file can
name domains and hosts as well, and the ownership file names owners, but
neither file is a destination itself.

## What is never contacted

scadenza sends no telemetry, no analytics, no crash report, no update check
and no version or health ping. The build metadata is printed from the linker
flags, or from the build information the Go toolchain embeds in the binary, and
nothing else (`internal/version/version.go`, `Current`). There is no code
path that fetches a release manifest or compares the local version with a
remote one.

The following searches were run over the whole repository on 2026-10-20 and
found no client other than the ones in the table above. The commands are given
so the claim can be repeated.

```sh
# Every HTTP client construction and request.
rg -n 'http\.Client|http\.NewRequest|http\.Transport' -g '*.go'

# Every process execution.
rg -n '"os/exec"|exec\.Command' -g '*.go'

# Every dial, in any package.
rg -n 'net\.Dial|DialContext|tls\.Dial|tls\.Client' -g '*.go'

# The convenience HTTP entry points.
rg -n 'http\.(Get|Post|Head|Do)\(' -g '*.go'

# The cloud and cluster SDK constructors.
rg -n 'NewForConfig|NewDefaultAzureCredential|azcertificates\.NewClient|rest\.Config' -g '*.go'

# Any other protocol, any listener, any other name lookup.
rg -n 'grpc|smtp|websocket|LookupHost|LookupIP|net\.Listen' -g '*.go'
```

What they return:

- The first search matches `internal/httpx/httpx.go` (the CT client) and the
  two CT source files, plus test files that use `httptest` servers.
- The second search matches only `test/e2e/kube_test.go`, which builds and runs
  the binary under test. No production code executes a process, apart from the
  two cases a library does it for the user: the Kubernetes exec credential
  plugin and the Azure developer credentials, both listed above.
- The third search matches `internal/httpx/httpx.go` and
  `internal/tlsprobe/tlsprobe.go`, plus test helpers.
- The fourth search returns nothing: no code calls `http.Get`, `http.Post`,
  `http.Head` or `http.Do`.
- The fifth search matches `internal/kube/config.go` and
  `internal/azurekv/client.go`, plus test files.
- The sixth search matches `internal/tlsprobe/tlsprobe.go` (the resolver
  interface) and test files only.

No other outbound call was found. The only names the program resolves are the
ones in the table above.

## Environment variables that change network behaviour

| Variable | What it changes | Source |
| --- | --- | --- |
| `SCADENZA_CERTSPOTTER_KEY` | The Cert Spotter API key. Sent as a bearer token to `api.certspotter.com` and nowhere else. Never accepted as a flag and never printed. | `internal/cli/ct.go` (`productionCTDependencies`) |
| `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` (and the lower-case forms) | The proxy used by the CT clients, the Azure SDK and the Kubernetes client. `NO_PROXY` decides which hosts bypass it. The TLS probe ignores all of them and dials the target directly. | `internal/httpx/httpx.go` (`New`, `http.ProxyFromEnvironment`); `azure-sdk-for-go/sdk/internal` v1.13.0 `transport/transport.go` (`DefaultHTTPClient`); `k8s.io/client-go` v0.37.1 `rest/config.go` (`Config.Proxy`, nil means `http.ProxyFromEnvironment`) |
| `KUBECONFIG` | The kubeconfig file the Kubernetes client loads. `--kubeconfig` overrides it. | `internal/kube/config.go` (`restConfig`); `k8s.io/client-go` v0.37.1 `tools/clientcmd/loader.go` (`NewDefaultClientConfigLoadingRules`, `RecommendedConfigPathEnvVar`) |
| `KUBERNETES_SERVICE_HOST`, `KUBERNETES_SERVICE_PORT` | The API server host and port when the in-cluster configuration is used instead of a kubeconfig. | `k8s.io/client-go` v0.37.1 `rest/config.go` (`InClusterConfig`); `tools/clientcmd/client_config.go` (`inClusterClientConfig.Possible`) |
| `AZURE_TOKEN_CREDENTIALS` | Which credentials the default chain may use. `prod` allows only the cloud credentials, `dev` only the developer tools. This decides whether Entra ID, the instance metadata service or a local tool is contacted. | `azidentity` v1.15.0 `default_azure_credential.go` (`NewDefaultAzureCredential`) |
| `AZURE_AUTHORITY_HOST` | The Entra ID host used for token requests. The default is `login.microsoftonline.com`. | `azidentity` v1.15.0 `azidentity.go` (`setAuthorityHost`); `azcore` v1.23.3 `cloud/cloud.go` |
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_CLIENT_CERTIFICATE_PATH`, `AZURE_CLIENT_CERTIFICATE_PASSWORD`, `AZURE_USERNAME`, `AZURE_PASSWORD`, `AZURE_CLIENT_SEND_CERTIFICATE_CHAIN` | The credentials the environment credential sends to the token endpoint. | `azidentity` v1.15.0 `azidentity.go` (names), `environment_credential.go` (`NewEnvironmentCredential`) |
| `AZURE_FEDERATED_TOKEN_FILE` | The federated token file the workload identity credential reads and sends to the token endpoint. | `azidentity` v1.15.0 `azidentity.go` (`azureFederatedTokenFile`), `workload_identity.go` |
| `AZURE_ADDITIONALLY_ALLOWED_TENANTS`, `AZURE_REGIONAL_AUTHORITY_NAME` | Extra tenants the credential may authenticate to, and the regional authority it uses. A regional authority makes the SDK read the region from the instance metadata service, `GET /metadata/instance/compute`, with a two-second timeout. | `azidentity` v1.15.0 `azidentity.go` (`azureRegionalAuthorityName`), `confidential_client.go` (`NewConfidentialClient`); `microsoft-authentication-library-for-go` v1.10.1 `apps/internal/oauth/ops/authority/authority.go` (`detectRegion`) |
| `IDENTITY_ENDPOINT`, `IDENTITY_HEADER`, `IDENTITY_SERVER_THUMBPRINT`, `MSI_ENDPOINT`, `MSI_SECRET`, `IMDS_ENDPOINT`, `DEFAULT_IDENTITY_CLIENT_ID` | Which managed identity endpoint is used instead of `169.254.169.254`: App Service, Cloud Shell, Azure Machine Learning or Azure Arc. | `azidentity` v1.15.0 `managed_identity_client.go`; `microsoft-authentication-library-for-go` v1.10.1 `apps/managedidentity/managedidentity.go` (`GetSource`) |

No other environment variable changes where the program connects.

## Running scadenza in a restricted network

Allow only what the run needs. Nothing is contacted unless the matching option
is used.

- `ct <domain>`: allow `api.certspotter.com:443` and `crt.sh:443`, plus DNS.
  Set `SCADENZA_CERTSPOTTER_KEY` only if the run needs the higher Cert Spotter
  quota; the key then leaves the machine with every Cert Spotter request.
- `scan` with only `--host` or `--domain` and `--from-ct=false`: allow the
  named hosts on their port, 443 by default. The CT sources are not contacted
  with `--from-ct=false`. No proxy is used for probes, so the firewall has to
  allow the target hosts directly.
- `scan --from-ct` with `--domain`: add `api.certspotter.com:443` and
  `crt.sh:443`, and allow the hosts that the returned names resolve to. A
  name that resolves inside the network is dialled; a name that resolves to a
  loopback or a metadata address is not, because every CT-derived host is
  probed with the special-address guard.
- `scan --kube`: allow the API server host and port from the kubeconfig, plus
  DNS. The exec credential plugin runs locally and may need its own access.
- `scan --azure-keyvault`: allow the vault host on 443, the Entra ID host
  `login.microsoftonline.com:443` when a cloud credential is used, and
  `169.254.169.254:80` when the managed identity credential is used. Set
  `AZURE_TOKEN_CREDENTIALS` to the one credential the run should use, so a
  developer login on the machine cannot be used instead.

To avoid every destination except the hosts you name, use `scan` with
`--from-ct=false`, without `--kube` and without `--azure-keyvault`. The only
connections left are the probes of the named hosts and DNS. `version` never
touches the network.
