package azurekv

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
)

type credentialFactory func() (azcore.TokenCredential, error)

type sdkAPI struct {
	newCredential credentialFactory
	options       *azcertificates.ClientOptions

	credentialOnce sync.Once
	credential     azcore.TokenCredential
	credentialErr  error

	mu      sync.Mutex
	clients map[string]*azcertificates.Client
	pagers  map[string]*azcorePager
}

type azcorePager struct {
	nextPage func(context.Context) (azcertificates.ListCertificatePropertiesResponse, error)
	more     func() bool
}

// perTryTimeout bounds a single HTTP try against a Key Vault. The scan
// command context carries no deadline, so without it a hung vault would block
// a scan forever.
const perTryTimeout = 30 * time.Second

// maxRetries is the number of retries after the first try. Three is the
// azcore default and bounds a failing vault to four attempts.
const maxRetries = 3

func newDefaultCredential() (azcore.TokenCredential, error) {
	return azidentity.NewDefaultAzureCredential(nil)
}

func newSDKAPI(factory credentialFactory, userAgent string) *sdkAPI {
	options := &azcertificates.ClientOptions{}
	if userAgent != "" {
		options.Telemetry.ApplicationID = userAgent
	}
	return newSDKAPIWithOptions(factory, options)
}

func newSDKAPIWithOptions(factory credentialFactory, options *azcertificates.ClientOptions) *sdkAPI {
	local := azcertificates.ClientOptions{}
	if options != nil {
		local = *options
	}
	// A hung vault must not hang a scan: bound every try and cap the retries.
	// A caller that injects its own values keeps them.
	if local.Retry.TryTimeout == 0 {
		local.Retry.TryTimeout = perTryTimeout
	}
	if local.Retry.MaxRetries == 0 {
		local.Retry.MaxRetries = maxRetries
	}
	return &sdkAPI{
		newCredential: factory,
		options:       &local,
		clients:       map[string]*azcertificates.Client{},
		pagers:        map[string]*azcorePager{},
	}
}

func (a *sdkAPI) client(vaultURL string) (*azcertificates.Client, error) {
	a.mu.Lock()
	if client := a.clients[vaultURL]; client != nil {
		a.mu.Unlock()
		return client, nil
	}
	a.mu.Unlock()

	a.credentialOnce.Do(func() {
		a.credential, a.credentialErr = a.newCredential()
	})
	if a.credentialErr != nil {
		return nil, a.credentialErr
	}
	client, err := azcertificates.NewClient(vaultURL, a.credential, a.options)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	if existing := a.clients[vaultURL]; existing != nil {
		a.mu.Unlock()
		return existing, nil
	}
	a.clients[vaultURL] = client
	a.mu.Unlock()
	return client, nil
}

func (a *sdkAPI) ListCertificateProperties(ctx context.Context, vaultURL, continuation string) (CertificatePage, error) {
	client, err := a.client(vaultURL)
	if err != nil {
		return CertificatePage{}, classifySDKError(ctx, vaultURL, err)
	}

	a.mu.Lock()
	pager := a.pagers[vaultURL]
	if continuation == "" {
		sdkPager := client.NewListCertificatePropertiesPager(nil)
		pager = &azcorePager{
			nextPage: func(ctx context.Context) (azcertificates.ListCertificatePropertiesResponse, error) {
				return sdkPager.NextPage(ctx)
			},
			more: sdkPager.More,
		}
		a.pagers[vaultURL] = pager
	} else if pager == nil {
		a.mu.Unlock()
		return CertificatePage{}, &Error{Problem: Problem{Kind: ErrorInvalid, VaultHost: vaultHost(vaultURL)}}
	}
	a.mu.Unlock()

	response, err := pager.nextPage(ctx)
	if err != nil {
		return CertificatePage{}, classifySDKError(ctx, vaultURL, err)
	}
	page := CertificatePage{}
	if response.NextLink != nil {
		page.NextLink = *response.NextLink
	}
	for _, item := range response.Value {
		if item == nil {
			continue
		}
		property := CertificateProperty{Tags: sdkTags(item.Tags)}
		if item.ID != nil {
			property.ID = string(*item.ID)
		}
		applyAttributes(&property.Enabled, &property.NotBefore, &property.NotAfter, item.Attributes)
		page.Properties = append(page.Properties, property)
	}
	if !pager.more() {
		a.mu.Lock()
		delete(a.pagers, vaultURL)
		a.mu.Unlock()
	}
	return page, nil
}

func (a *sdkAPI) GetCertificatePolicy(ctx context.Context, vaultURL, name, _ string) (Policy, error) {
	client, err := a.client(vaultURL)
	if err != nil {
		return Policy{}, classifySDKError(ctx, vaultURL, err)
	}
	response, err := client.GetCertificatePolicy(ctx, name, nil)
	if err != nil {
		return Policy{}, classifySDKError(ctx, vaultURL, err)
	}
	return sdkPolicy(response.CertificatePolicy), nil
}

func (a *sdkAPI) GetCertificate(ctx context.Context, vaultURL, name, version string) (CertificateBundle, error) {
	client, err := a.client(vaultURL)
	if err != nil {
		return CertificateBundle{}, classifySDKError(ctx, vaultURL, err)
	}
	response, err := client.GetCertificate(ctx, name, version, nil)
	if err != nil {
		return CertificateBundle{}, classifySDKError(ctx, vaultURL, err)
	}
	bundle := CertificateBundle{
		CER:  append([]byte(nil), response.CER...),
		Tags: sdkTags(response.Tags),
	}
	if response.ID != nil {
		bundle.Version = response.ID.Version()
	}
	if response.ContentType != nil {
		bundle.ContentType = *response.ContentType
	}
	applyAttributes(&bundle.Enabled, &bundle.NotBefore, &bundle.NotAfter, response.Attributes)
	return bundle, nil
}

func sdkPolicy(input azcertificates.CertificatePolicy) Policy {
	result := Policy{Issuer: "Unknown", LifetimeActions: []LifetimeAction{}}
	if input.IssuerParameters != nil && input.IssuerParameters.Name != nil {
		result.Issuer = *input.IssuerParameters.Name
	}
	if input.X509CertificateProperties != nil && input.X509CertificateProperties.ValidityInMonths != nil {
		value := int(*input.X509CertificateProperties.ValidityInMonths)
		result.ValidityMonths = &value
	}
	if input.SecretProperties != nil && input.SecretProperties.ContentType != nil {
		result.ContentType = *input.SecretProperties.ContentType
	}
	for _, item := range input.LifetimeActions {
		if item == nil {
			continue
		}
		action := LifetimeAction{}
		if item.Action != nil && item.Action.ActionType != nil {
			action.Type = string(*item.Action.ActionType)
		}
		if item.Trigger != nil {
			if item.Trigger.DaysBeforeExpiry != nil {
				value := int(*item.Trigger.DaysBeforeExpiry)
				action.DaysBeforeExpiry = &value
			}
			if item.Trigger.LifetimePercentage != nil {
				value := int(*item.Trigger.LifetimePercentage)
				action.LifetimePercentage = &value
			}
		}
		result.LifetimeActions = append(result.LifetimeActions, action)
	}
	return result
}

func applyAttributes(enabled **bool, notBefore, notAfter *time.Time, attributes *azcertificates.CertificateAttributes) {
	if attributes == nil {
		return
	}
	*enabled = attributes.Enabled
	if attributes.NotBefore != nil {
		*notBefore = *attributes.NotBefore
	}
	if attributes.Expires != nil {
		*notAfter = *attributes.Expires
	}
}

func sdkTags(input map[string]*string) map[string]string {
	if len(input) == 0 {
		return map[string]string{}
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		if value != nil {
			result[key] = *value
		}
	}
	return result
}

func classifySDKError(ctx context.Context, vaultURL string, err error) error {
	host := vaultHost(vaultURL)
	if ctx.Err() != nil {
		return &Error{Problem: Problem{Kind: ErrorCanceled, VaultHost: host}}
	}
	var responseErr *azcore.ResponseError
	if errors.As(err, &responseErr) {
		kind := ErrorUnreachable
		switch responseErr.StatusCode {
		case http.StatusUnauthorized:
			kind = ErrorUnauthorized
		case http.StatusForbidden:
			kind = ErrorForbidden
		}
		return &Error{Problem: Problem{Kind: kind, HTTPStatus: responseErr.StatusCode, VaultHost: host}}
	}
	return &Error{Problem: Problem{Kind: ErrorUnreachable, VaultHost: host}}
}
