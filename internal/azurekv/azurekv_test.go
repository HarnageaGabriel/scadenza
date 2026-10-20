package azurekv

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/HarnageaGabriel/scadenza/internal/owner"
)

type fakeAPI struct {
	mu           sync.Mutex
	pages        map[string]CertificatePage
	pagesByVault map[string]map[string]CertificatePage
	listErrors   map[string]error
	bundle       CertificateBundle
	bundles      map[string]CertificateBundle
	policy       Policy
	getError     error
	getErrors    map[string]error
	getCalls     []string
}

func (f *fakeAPI) ListCertificateProperties(_ context.Context, vault, continuation string) (CertificatePage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.listErrors[vault]; err != nil {
		return CertificatePage{}, err
	}
	if pages := f.pagesByVault[vault]; pages != nil {
		return pages[continuation], nil
	}
	return f.pages[continuation], nil
}

func (f *fakeAPI) GetCertificate(_ context.Context, vault, name, version string) (CertificateBundle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := vault + "|" + name + "|" + version
	f.getCalls = append(f.getCalls, key)
	if err := f.getErrors[key]; err != nil {
		return CertificateBundle{}, err
	}
	if f.getError != nil {
		return CertificateBundle{}, f.getError
	}
	if bundle, ok := f.bundles[key]; ok {
		return bundle, nil
	}
	return f.bundle, nil
}

func (f *fakeAPI) GetCertificatePolicy(_ context.Context, _, _, _ string) (Policy, error) {
	return f.policy, nil
}

func certificateDER(t *testing.T) []byte {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "api.example.com"},
		DNSNames:  []string{"api.example.com", "API.EXAMPLE.COM"},
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestSourceStreamsPagesAndBuildsSafeFacts(t *testing.T) {
	der := certificateDER(t)
	enabled := true
	api := &fakeAPI{
		pages: map[string]CertificatePage{
			"":      {Properties: []CertificateProperty{{ID: "https://demo.vault.azure.net/certificates/api"}}, NextLink: "page2"},
			"page2": {Properties: []CertificateProperty{{ID: "https://demo.vault.azure.net/certificates/api/v2"}}},
		},
		bundles: map[string]CertificateBundle{
			"https://demo.vault.azure.net|api|":   {CER: der, Version: "v3", Enabled: &enabled, Tags: map[string]string{"scadenza.io/owner": "team-api"}, ContentType: "application/x-pem-file"},
			"https://demo.vault.azure.net|api|v2": {CER: der, Version: "v2", Enabled: &enabled, Tags: map[string]string{"scadenza.io/owner": "team-api"}, ContentType: "application/x-pem-file"},
		},
		policy: Policy{Issuer: "DigiCert", ValidityMonths: intPtr(3), LifetimeActions: []LifetimeAction{{Type: "AutoRenew", DaysBeforeExpiry: intPtr(30)}}},
	}
	owners, err := owner.ParseConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewSource(api, LoadOptions{VaultURLs: []string{"https://demo.vault.azure.net"}, QPS: 100000, Owners: owners})
	if err != nil {
		t.Fatal(err)
	}
	certificates, problems, err := source.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 0 || len(certificates) != 2 {
		t.Fatalf("certificates=%d problems=%v", len(certificates), problems)
	}
	got := certificates[0]
	wantFingerprint := sha256.Sum256(der)
	if got.Fingerprint != hex.EncodeToString(wantFingerprint[:]) || got.Serial != "2a" || len(got.Names) != 1 {
		t.Fatalf("certificate=%+v", got)
	}
	if got.Facts.Issuer != "DigiCert" || got.Facts.ContentType == "" || got.Owners[0].Source != owner.Source("tag") {
		t.Fatalf("facts=%+v owners=%+v", got.Facts, got.Owners)
	}
	if certificates[0].Facts.Version != "v2" || certificates[1].Facts.Version != "v3" {
		t.Fatalf("versions=%q,%q", certificates[0].Facts.Version, certificates[1].Facts.Version)
	}
	if !contains(api.getCalls, "https://demo.vault.azure.net|api|") {
		t.Fatalf("latest-version get not called: %v", api.getCalls)
	}
}

func TestSourceForbiddenIsPartialAndCancellationIsSafe(t *testing.T) {
	api := &fakeAPI{pages: map[string]CertificatePage{"": {Properties: []CertificateProperty{{ID: "https://demo.vault.azure.net/certificates/api/v1"}}}}, getError: &Error{Problem: Problem{Kind: ErrorForbidden, HTTPStatus: 403}}}
	source, err := NewSource(api, LoadOptions{VaultURLs: []string{"https://demo.vault.azure.net"}, QPS: 100000})
	if err != nil {
		t.Fatal(err)
	}
	certificates, problems, err := source.Scan(context.Background())
	if err != nil || len(certificates) != 0 || len(problems) != 1 || problems[0].VaultHost != "demo.vault.azure.net" {
		t.Fatalf("certificates=%v problems=%v err=%v", certificates, problems, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = source.Scan(ctx)
	var sourceErr *Error
	if !errors.As(err, &sourceErr) || sourceErr.Problem.Kind != ErrorCanceled {
		t.Fatalf("cancel err=%v", err)
	}
}

func TestSourceKeepsDisabledCertificates(t *testing.T) {
	der := certificateDER(t)
	disabled := false
	api := &fakeAPI{
		pages:  map[string]CertificatePage{"": {Properties: []CertificateProperty{{ID: "https://demo.vault.azure.net/certificates/api"}}}},
		bundle: CertificateBundle{CER: der, Version: "v1", Enabled: &disabled},
	}
	source, err := NewSource(api, LoadOptions{VaultURLs: []string{"https://demo.vault.azure.net"}, QPS: 100000})
	if err != nil {
		t.Fatal(err)
	}
	certificates, problems, err := source.Scan(context.Background())
	if err != nil || len(problems) != 0 || len(certificates) != 1 || certificates[0].Facts.Enabled == nil || *certificates[0].Facts.Enabled {
		t.Fatalf("certificates=%v problems=%v err=%v", certificates, problems, err)
	}
}

func TestSourceKeepsListedVersionWhenBundleVersionIsMissing(t *testing.T) {
	der := certificateDER(t)
	for _, test := range []struct {
		name        string
		propertyID  string
		wantVersion string
	}{
		{name: "versioned list ID", propertyID: "https://demo.vault.azure.net/certificates/api/v1", wantVersion: "v1"},
		{name: "versionless list ID", propertyID: "https://demo.vault.azure.net/certificates/api", wantVersion: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			api := &fakeAPI{
				pages:  map[string]CertificatePage{"": {Properties: []CertificateProperty{{ID: test.propertyID}}}},
				bundle: CertificateBundle{CER: der},
			}
			source, err := NewSource(api, LoadOptions{VaultURLs: []string{"https://demo.vault.azure.net"}, QPS: 100000})
			if err != nil {
				t.Fatal(err)
			}
			certificates, problems, err := source.Scan(context.Background())
			if err != nil || len(problems) != 0 || len(certificates) != 1 || certificates[0].Facts.Version != test.wantVersion {
				t.Fatalf("certificates=%v problems=%v err=%v", certificates, problems, err)
			}
		})
	}
}

func TestSourceContinuesAfterVaultFailure(t *testing.T) {
	der := certificateDER(t)
	first := "https://first.vault.azure.net"
	second := "https://second.vault.azure.net"
	api := &fakeAPI{
		pagesByVault: map[string]map[string]CertificatePage{
			first: {"": {Properties: []CertificateProperty{{ID: first + "/certificates/api"}}}},
		},
		listErrors: map[string]error{second: &Error{Problem: Problem{Kind: ErrorUnauthorized, HTTPStatus: 401}}},
		bundle:     CertificateBundle{CER: der, Version: "v1"},
	}
	source, err := NewSource(api, LoadOptions{VaultURLs: []string{first, second}, QPS: 100000})
	if err != nil {
		t.Fatal(err)
	}
	certificates, problems, err := source.Scan(context.Background())
	if err != nil || len(certificates) != 1 || len(problems) != 1 || !problems[0].VaultUnavailable || problems[0].VaultHost != "second.vault.azure.net" {
		t.Fatalf("certificates=%v problems=%v err=%v", certificates, problems, err)
	}
}

func TestSourceSkipsBadItemsWithoutFailingVault(t *testing.T) {
	der := certificateDER(t)
	vault := "https://demo.vault.azure.net"
	api := &fakeAPI{
		pages: map[string]CertificatePage{"": {Properties: []CertificateProperty{
			{ID: vault + "/certificates/good"},
			{ID: vault + "/certificates/deleted"},
			{ID: vault + "/certificates/pending"},
			{ID: vault + "/keys/not-a-certificate"},
		}}},
		bundles: map[string]CertificateBundle{
			vault + "|good|":    {CER: der, Version: "v1"},
			vault + "|pending|": {CER: nil, Version: "v2"},
		},
		getErrors: map[string]error{
			vault + "|deleted|": &Error{Problem: Problem{Kind: ErrorUnreachable, HTTPStatus: 404}},
		},
	}
	source, err := NewSource(api, LoadOptions{VaultURLs: []string{vault}, QPS: 100000})
	if err != nil {
		t.Fatal(err)
	}
	certificates, problems, err := source.Scan(context.Background())
	if err != nil || len(certificates) != 1 || len(problems) != 3 {
		t.Fatalf("certificates=%v problems=%v err=%v", certificates, problems, err)
	}
	for _, problem := range problems {
		if problem.VaultUnavailable {
			t.Fatalf("item problem marked vault unavailable: %+v", problem)
		}
	}
}

func TestSourceItemUnauthorizedFailsOnlyThatVault(t *testing.T) {
	der := certificateDER(t)
	vault := "https://demo.vault.azure.net"
	api := &fakeAPI{
		pages: map[string]CertificatePage{"": {Properties: []CertificateProperty{
			{ID: vault + "/certificates/good"},
			{ID: vault + "/certificates/unauthorized"},
		}}},
		bundles: map[string]CertificateBundle{
			vault + "|good|": {CER: der, Version: "v1"},
		},
		getErrors: map[string]error{
			vault + "|unauthorized|": &Error{Problem: Problem{Kind: ErrorUnauthorized, HTTPStatus: 401}},
		},
	}
	source, err := NewSource(api, LoadOptions{VaultURLs: []string{vault}, QPS: 100000})
	if err != nil {
		t.Fatal(err)
	}
	certificates, problems, err := source.Scan(context.Background())
	if err != nil || len(certificates) != 0 || len(problems) != 1 || !problems[0].VaultUnavailable {
		t.Fatalf("certificates=%v problems=%v err=%v", certificates, problems, err)
	}
}

func TestValidationAndHelpers(t *testing.T) {
	for _, invalid := range []string{"http://demo.vault.azure.net", "https://user@demo.vault.azure.net", "https://demo.vault.azure.net/path", "not a url"} {
		if ValidateVaultURL(invalid) == nil {
			t.Fatalf("accepted %q", invalid)
		}
	}
	if host, err := ParseVaultHost("https://demo.vault.azure.net"); err != nil || host != "demo.vault.azure.net" {
		t.Fatalf("host=%q err=%v", host, err)
	}
	if _, err := NewSource(nil, LoadOptions{VaultURLs: []string{"https://demo.vault.azure.net"}}); err == nil {
		t.Fatal("nil API accepted")
	}
	if _, _, ok := splitCertificateID("https://demo.vault.azure.net/keys/nope"); ok {
		t.Fatal("key ID accepted")
	}
	if got := safeError(errors.New("token secret"), "https://demo.vault.azure.net").Error(); got != string(ErrorUnreachable) {
		t.Fatalf("safe error=%q", got)
	}
}

// paddedVaultURIs are vault URIs with surrounding whitespace. They are
// rejected instead of trimmed, because the same string is used for the
// request and for the reported vault host.
var paddedVaultURIs = []struct {
	name  string
	value string
}{
	{name: "trailing space", value: "https://demo.vault.azure.net "},
	{name: "leading space", value: " https://demo.vault.azure.net"},
	{name: "trailing newline", value: "https://demo.vault.azure.net\n"},
	{name: "leading space and trailing newline", value: " https://demo.vault.azure.net\n"},
	{name: "non breaking space", value: "https://demo.vault.azure.net\u00a0"},
}

func TestValidateVaultURLRejectsSurroundingWhitespace(t *testing.T) {
	for _, test := range paddedVaultURIs {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateVaultURL(test.value)
			if !errors.Is(err, ErrInvalidVaultURI) {
				t.Fatalf("ValidateVaultURL(%q) err = %v, want ErrInvalidVaultURI", test.value, err)
			}
			var uriErr *VaultURIError
			if !errors.As(err, &uriErr) {
				t.Fatalf("err = %v, want a *VaultURIError", err)
			}
			if !strings.Contains(uriErr.Value, "demo.vault.azure.net") {
				t.Fatalf("the error does not name the value: %v", err)
			}
			if host, err := ParseVaultHost(test.value); err == nil {
				t.Fatalf("ParseVaultHost(%q) = %q, want an error", test.value, host)
			}
			_, err = NewSource(&fakeAPI{}, LoadOptions{VaultURLs: []string{test.value}})
			if err == nil {
				t.Fatalf("NewSource accepted %q", test.value)
			}
			var sourceErr *Error
			if !errors.As(err, &sourceErr) || sourceErr.Problem.Kind != ErrorInvalid {
				t.Fatalf("NewSource err = %v, want an invalid source error", err)
			}
		})
	}
}

func TestValidateVaultURLErrorNamesTheValueSafely(t *testing.T) {
	err := ValidateVaultURL("https://user:secret@demo.vault.azure.net\n")
	if err == nil {
		t.Fatal("accepted a vault URI with credentials and a trailing newline")
	}
	if strings.Contains(err.Error(), "\n") {
		t.Fatalf("the error carries a raw newline: %q", err.Error())
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("the error leaked the credential: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "demo.vault.azure.net") {
		t.Fatalf("the error does not name the value: %q", err.Error())
	}
	var uriErr *VaultURIError
	if !errors.As(err, &uriErr) || !strings.Contains(uriErr.Value, "redacted@demo.vault.azure.net") {
		t.Fatalf("value = %q, want the redacted host", uriErr.Value)
	}
}

type staticCredential struct{}

func (staticCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "test", ExpiresOn: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)}, nil
}

func sdkTestAPI(server *httptest.Server, factory credentialFactory) *sdkAPI {
	return newSDKAPIWithOptions(factory, &azcertificates.ClientOptions{
		ClientOptions:                        azcore.ClientOptions{Transport: server.Client()},
		DisableChallengeResourceVerification: true,
	})
}

func TestSDKAdapterReadOnlyEndpointsTwoPagesAndDecoding(t *testing.T) {
	der := certificateDER(t)
	var mu sync.Mutex
	var paths []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/certificates" && r.URL.Query().Get("page") == "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"value":    []any{map[string]any{"id": serverURL(r) + "/certificates/api", "attributes": map[string]any{"enabled": true}, "tags": map[string]string{"team": "api"}}},
				"nextLink": serverURL(r) + "/certificates?page=2",
			})
		case r.URL.Path == "/certificates" && r.URL.Query().Get("page") == "2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"value": []any{map[string]any{"id": serverURL(r) + "/certificates/api/v2"}},
			})
		case strings.HasSuffix(r.URL.Path, "/policy"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":       map[string]any{"name": "GlobalSign"},
				"x509_props":   map[string]any{"validity_months": 3},
				"secret_props": map[string]any{"contentType": "application/x-pem-file"},
				"lifetime_actions": []any{map[string]any{
					"action":  map[string]any{"action_type": "EmailContacts"},
					"trigger": map[string]any{"days_before_expiry": 20},
				}},
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":          serverURL(r) + r.URL.Path,
				"cer":         der,
				"attributes":  map[string]any{"enabled": true},
				"tags":        map[string]string{"team": "api"},
				"contentType": "application/x-pem-file",
				"x5t":         "c2hhMS1pcy1ub3QtdXNlZA",
			})
		}
	}))
	defer server.Close()

	credentialCalls := 0
	api := sdkTestAPI(server, func() (azcore.TokenCredential, error) {
		credentialCalls++
		return staticCredential{}, nil
	})
	if credentialCalls != 0 {
		t.Fatal("credential was created eagerly")
	}
	first, err := api.ListCertificateProperties(context.Background(), server.URL, "")
	if err != nil || len(first.Properties) != 1 || first.NextLink == "" {
		t.Fatalf("first page=%+v err=%v", first, err)
	}
	second, err := api.ListCertificateProperties(context.Background(), server.URL, first.NextLink)
	if err != nil || len(second.Properties) != 1 || second.NextLink != "" {
		t.Fatalf("second page=%+v err=%v", second, err)
	}
	if credentialCalls != 1 {
		t.Fatalf("credential calls=%d, want 1", credentialCalls)
	}
	policyValue, err := api.GetCertificatePolicy(context.Background(), server.URL, "api", "v1")
	if err != nil || policyValue.Issuer != "GlobalSign" || policyValue.ValidityMonths == nil || *policyValue.ValidityMonths != 3 {
		t.Fatalf("policy=%+v err=%v", policyValue, err)
	}
	bundle, err := api.GetCertificate(context.Background(), server.URL, "api", "v1")
	if err != nil || len(bundle.CER) == 0 || bundle.ContentType == "" || bundle.Version != "v1" {
		t.Fatalf("bundle=%+v err=%v", bundle, err)
	}
	for _, path := range paths {
		if strings.Contains(path, "/secrets/") || strings.Contains(path, "/keys/") {
			t.Fatalf("unsafe endpoint %s", path)
		}
	}
}

func TestSDKAdapterMaps401And403WithoutRawErrors(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		want   ErrorKind
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, want: ErrorUnauthorized},
		{name: "forbidden", status: http.StatusForbidden, want: ErrorForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if test.status == http.StatusUnauthorized {
					w.Header().Set("WWW-Authenticate", `Bearer authorization="https://login.microsoftonline.com/tenant", resource="https://vault.azure.net"`)
				}
				w.WriteHeader(test.status)
			}))
			defer server.Close()
			api := sdkTestAPI(server, func() (azcore.TokenCredential, error) { return staticCredential{}, nil })
			_, err := api.ListCertificateProperties(context.Background(), server.URL, "")
			assertKind(t, err, test.want)
			if strings.Contains(err.Error(), server.URL) {
				t.Fatalf("raw SDK error leaked: %v", err)
			}
		})
	}
}

func TestSDKAdapterCancellationAndValidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := classifySDKError(ctx, "https://demo.vault.azure.net", context.Canceled)
	assertKind(t, err, ErrorCanceled)
	if _, err := ParseVaultHost("not a vault uri"); err == nil {
		t.Fatal("ParseVaultHost accepted an invalid URI")
	}
	if _, err := NewSource(&fakeAPI{pages: map[string]CertificatePage{}}, LoadOptions{
		VaultURLs: []string{"https://demo.vault.azure.net", "https://demo.vault.azure.net"},
	}); err != nil {
		t.Fatalf("duplicate vault URI rejected: %v", err)
	}
}

func serverURL(r *http.Request) string { return "https://" + r.Host }
func intPtr(value int) *int            { return &value }

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func assertKind(t *testing.T, err error, want ErrorKind) {
	t.Helper()
	var sourceErr *Error
	if !errors.As(err, &sourceErr) || sourceErr.Problem.Kind != want {
		t.Fatalf("err = %v, want kind %s", err, want)
	}
}
