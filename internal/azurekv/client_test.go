package azurekv

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	azcertfake "github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates/fake"
	"github.com/HarnageaGabriel/scadenza/internal/owner"
	"github.com/google/go-cmp/cmp"
)

// fakeVaultURL is the vault used by the fake server tests. The URL is only
// used to build request paths because the SDK fake transport never reaches
// the network.
const fakeVaultURL = "https://vault.example.net"

// fakeCredential is a test-only credential. It never contacts a network and
// fails fast when the caller context is already done.
type fakeCredential struct{}

func (fakeCredential) GetToken(ctx context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if err := ctx.Err(); err != nil {
		return azcore.AccessToken{}, err
	}
	return azcore.AccessToken{Token: "fake-access-token", ExpiresOn: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)}, nil
}

// newFakeAPI wires the production SDK adapter to the SDK fake server. The
// transport is injected through the client options so no request can leave
// the process.
func newFakeAPI(srv *azcertfake.Server) *sdkAPI {
	return newFakeAPIWithTransport(azcertfake.NewServerTransport(srv))
}

// newFakeAPIWithTransport is newFakeAPI with an explicit transport.
func newFakeAPIWithTransport(transport policy.Transporter) *sdkAPI {
	options := &azcertificates.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: transport,
			Retry:     policy.RetryOptions{MaxRetries: -1},
		},
		DisableChallengeResourceVerification: true,
	}
	return newSDKAPIWithOptions(func() (azcore.TokenCredential, error) { return fakeCredential{}, nil }, options)
}

// canceledGuardTransport keeps a canceled request away from the SDK fake
// server. The fake dispatcher closes its result channel as soon as the
// request context is done, and the worker goroutine can then send on the
// closed channel and panic the test binary. The guard reports the context
// error instead, which is what a real transport does for a canceled request.
type canceledGuardTransport struct {
	inner policy.Transporter
}

func (t canceledGuardTransport) Do(req *http.Request) (*http.Response, error) {
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	return t.inner.Do(req)
}

// policyIntPtr returns a pointer to an int for the policy comparison.
func policyIntPtr(value int) *int {
	return &value
}

// testCertificateDER builds a throwaway certificate so the scan can be
// checked against real certificate bytes.
func testCertificateDER(t *testing.T, name string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(int64(len(name)) + 1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

// assertProblem checks the safe classification returned by the adapter.
func assertProblem(t *testing.T, err error, kind ErrorKind, status int) {
	t.Helper()
	var sourceErr *Error
	if !errors.As(err, &sourceErr) {
		t.Fatalf("err = %v, want an *Error", err)
	}
	if sourceErr.Problem.Kind != kind {
		t.Fatalf("kind = %q, want %q", sourceErr.Problem.Kind, kind)
	}
	if sourceErr.Problem.HTTPStatus != status {
		t.Fatalf("http status = %d, want %d", sourceErr.Problem.HTTPStatus, status)
	}
	if sourceErr.Problem.VaultHost != "vault.example.net" {
		t.Fatalf("vault host = %q, want %q", sourceErr.Problem.VaultHost, "vault.example.net")
	}
	var responseErr *azcore.ResponseError
	if errors.As(err, &responseErr) {
		t.Fatalf("raw SDK error leaked into the safe error: %v", responseErr)
	}
}

func TestClientListsEveryPageFromFakeServer(t *testing.T) {
	notBefore := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	expires := time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC)
	enabled := true
	team := "team-api"
	first := azcertificates.ID(fakeVaultURL + "/certificates/api")
	second := azcertificates.ID(fakeVaultURL + "/certificates/web")
	third := azcertificates.ID(fakeVaultURL + "/certificates/edge/v9")

	pager := azfake.PagerResponder[azcertificates.ListCertificatePropertiesResponse]{}
	pager.AddPage(http.StatusOK, azcertificates.ListCertificatePropertiesResponse{
		CertificatePropertiesListResult: azcertificates.CertificatePropertiesListResult{
			Value: []*azcertificates.CertificateProperties{
				{
					ID:         &first,
					Tags:       map[string]*string{"team": &team},
					Attributes: &azcertificates.CertificateAttributes{Enabled: &enabled, NotBefore: &notBefore, Expires: &expires},
				},
				{ID: &second},
			},
		},
	}, nil)
	pager.AddPage(http.StatusOK, azcertificates.ListCertificatePropertiesResponse{
		CertificatePropertiesListResult: azcertificates.CertificatePropertiesListResult{
			Value: []*azcertificates.CertificateProperties{{ID: &third}},
		},
	}, nil)

	srv := &azcertfake.Server{
		NewListCertificatePropertiesPager: func(_ *azcertificates.ListCertificatePropertiesOptions) azfake.PagerResponder[azcertificates.ListCertificatePropertiesResponse] {
			return pager
		},
	}
	api := newFakeAPI(srv)

	page, err := api.ListCertificateProperties(context.Background(), fakeVaultURL, "")
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if len(page.Properties) != 2 {
		t.Fatalf("first page properties = %d, want 2", len(page.Properties))
	}
	if page.NextLink == "" {
		t.Fatal("first page has no next link")
	}
	want := CertificateProperty{
		ID:        string(first),
		Enabled:   &enabled,
		NotBefore: notBefore,
		NotAfter:  expires,
		Tags:      map[string]string{"team": team},
	}
	if diff := cmp.Diff(want, page.Properties[0]); diff != "" {
		t.Fatalf("first property mismatch (-want +got):\n%s", diff)
	}
	wantSecond := CertificateProperty{ID: string(second), Tags: map[string]string{}}
	if diff := cmp.Diff(wantSecond, page.Properties[1]); diff != "" {
		t.Fatalf("second property mismatch (-want +got):\n%s", diff)
	}

	page, err = api.ListCertificateProperties(context.Background(), fakeVaultURL, page.NextLink)
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if len(page.Properties) != 1 || page.Properties[0].ID != string(third) {
		t.Fatalf("second page properties = %+v", page.Properties)
	}
	if page.NextLink != "" {
		t.Fatalf("second page next link = %q, want empty", page.NextLink)
	}
	api.mu.Lock()
	remaining := len(api.pagers)
	api.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("tracked pagers = %d, want 0", remaining)
	}
}

func TestClientRejectsContinuationWithoutFirstPage(t *testing.T) {
	srv := &azcertfake.Server{}
	api := newFakeAPI(srv)

	_, err := api.ListCertificateProperties(context.Background(), fakeVaultURL, fakeVaultURL+"/certificates?api-version=7.5&skiptoken=abc")
	assertProblem(t, err, ErrorInvalid, 0)
}

func TestClientMapsGetCertificateResponse(t *testing.T) {
	der := testCertificateDER(t, "api.example.com")
	notBefore := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	expires := time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC)
	enabled := true
	team := "team-api"
	contentType := "application/x-pem-file"
	versioned := azcertificates.ID(fakeVaultURL + "/certificates/api/v7")
	unversioned := azcertificates.ID(fakeVaultURL + "/certificates/api")

	for _, test := range []struct {
		name        string
		id          *azcertificates.ID
		wantVersion string
	}{
		{name: "version from response id", id: &versioned, wantVersion: "v7"},
		{name: "no response id", id: nil, wantVersion: ""},
		{name: "response id without version", id: &unversioned, wantVersion: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			srv := &azcertfake.Server{
				GetCertificate: func(_ context.Context, _ string, _ string, _ *azcertificates.GetCertificateOptions) (azfake.Responder[azcertificates.GetCertificateResponse], azfake.ErrorResponder) {
					resp := azfake.Responder[azcertificates.GetCertificateResponse]{}
					resp.SetResponse(http.StatusOK, azcertificates.GetCertificateResponse{
						Certificate: azcertificates.Certificate{
							ID:          test.id,
							CER:         der,
							Tags:        map[string]*string{"team": &team},
							ContentType: &contentType,
							Attributes:  &azcertificates.CertificateAttributes{Enabled: &enabled, NotBefore: &notBefore, Expires: &expires},
						},
					}, nil)
					return resp, azfake.ErrorResponder{}
				},
			}
			api := newFakeAPI(srv)

			bundle, err := api.GetCertificate(context.Background(), fakeVaultURL, "api", "v7")
			if err != nil {
				t.Fatalf("get certificate: %v", err)
			}
			if !bytes.Equal(bundle.CER, der) {
				t.Fatalf("cer bytes = %d, want %d", len(bundle.CER), len(der))
			}
			if bundle.Version != test.wantVersion {
				t.Fatalf("version = %q, want %q", bundle.Version, test.wantVersion)
			}
			if bundle.ContentType != contentType {
				t.Fatalf("content type = %q, want %q", bundle.ContentType, contentType)
			}
			if bundle.Enabled == nil || !*bundle.Enabled {
				t.Fatalf("enabled = %v, want true", bundle.Enabled)
			}
			if !bundle.NotBefore.Equal(notBefore) {
				t.Fatalf("not before = %s, want %s", bundle.NotBefore, notBefore)
			}
			if !bundle.NotAfter.Equal(expires) {
				t.Fatalf("not after = %s, want %s", bundle.NotAfter, expires)
			}
			if diff := cmp.Diff(map[string]string{"team": team}, bundle.Tags); diff != "" {
				t.Fatalf("tags mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestClientMapsGetCertificatePolicyResponse(t *testing.T) {
	issuer := "DigiCert"
	months := int32(3)
	contentType := "application/x-pem-file"
	actionType := azcertificates.CertificatePolicyActionEmailContacts
	days := int32(20)
	percentage := int32(80)

	for _, test := range []struct {
		name   string
		policy azcertificates.CertificatePolicy
		want   Policy
	}{
		{
			name: "full policy",
			policy: azcertificates.CertificatePolicy{
				IssuerParameters:          &azcertificates.IssuerParameters{Name: &issuer},
				X509CertificateProperties: &azcertificates.X509CertificateProperties{ValidityInMonths: &months},
				SecretProperties:          &azcertificates.SecretProperties{ContentType: &contentType},
				LifetimeActions: []*azcertificates.LifetimeAction{
					{
						Action:  &azcertificates.LifetimeActionType{ActionType: &actionType},
						Trigger: &azcertificates.LifetimeActionTrigger{DaysBeforeExpiry: &days, LifetimePercentage: &percentage},
					},
				},
			},
			want: Policy{
				Issuer:         "DigiCert",
				ValidityMonths: policyIntPtr(3),
				ContentType:    "application/x-pem-file",
				LifetimeActions: []LifetimeAction{
					{Type: "EmailContacts", DaysBeforeExpiry: policyIntPtr(20), LifetimePercentage: policyIntPtr(80)},
				},
			},
		},
		{
			name:   "empty policy",
			policy: azcertificates.CertificatePolicy{},
			want:   Policy{Issuer: "Unknown", LifetimeActions: []LifetimeAction{}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			srv := &azcertfake.Server{
				GetCertificatePolicy: func(_ context.Context, _ string, _ *azcertificates.GetCertificatePolicyOptions) (azfake.Responder[azcertificates.GetCertificatePolicyResponse], azfake.ErrorResponder) {
					resp := azfake.Responder[azcertificates.GetCertificatePolicyResponse]{}
					resp.SetResponse(http.StatusOK, azcertificates.GetCertificatePolicyResponse{CertificatePolicy: test.policy}, nil)
					return resp, azfake.ErrorResponder{}
				},
			}
			api := newFakeAPI(srv)

			got, err := api.GetCertificatePolicy(context.Background(), fakeVaultURL, "api", "v7")
			if err != nil {
				t.Fatalf("get policy: %v", err)
			}
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Fatalf("policy mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestClientClassifiesFakeServerErrors(t *testing.T) {
	for _, test := range []struct {
		status int
		want   ErrorKind
	}{
		{status: http.StatusUnauthorized, want: ErrorUnauthorized},
		{status: http.StatusForbidden, want: ErrorForbidden},
		{status: http.StatusNotFound, want: ErrorUnreachable},
		{status: http.StatusInternalServerError, want: ErrorUnreachable},
	} {
		t.Run(strconv.Itoa(test.status), func(t *testing.T) {
			marker := "MarkerBody" + strconv.Itoa(test.status)
			srv := &azcertfake.Server{
				GetCertificate: func(_ context.Context, _ string, _ string, _ *azcertificates.GetCertificateOptions) (azfake.Responder[azcertificates.GetCertificateResponse], azfake.ErrorResponder) {
					var errResp azfake.ErrorResponder
					errResp.SetResponseError(test.status, marker)
					return azfake.Responder[azcertificates.GetCertificateResponse]{}, errResp
				},
			}
			api := newFakeAPI(srv)

			_, err := api.GetCertificate(context.Background(), fakeVaultURL, "api", "v7")
			assertProblem(t, err, test.want, test.status)
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("response body leaked into the error: %q", err.Error())
			}
			if strings.Contains(err.Error(), "fake-access-token") {
				t.Fatalf("token leaked into the error: %q", err.Error())
			}
			if err.Error() != string(test.want) {
				t.Fatalf("error text = %q, want %q", err.Error(), string(test.want))
			}
		})
	}
}

func TestClientDropsRawSDKErrorText(t *testing.T) {
	body := "sensitive-response-body"
	srv := &azcertfake.Server{
		GetCertificate: func(_ context.Context, _ string, _ string, _ *azcertificates.GetCertificateOptions) (azfake.Responder[azcertificates.GetCertificateResponse], azfake.ErrorResponder) {
			var errResp azfake.ErrorResponder
			errResp.SetError(errors.New(body + " fake-access-token"))
			return azfake.Responder[azcertificates.GetCertificateResponse]{}, errResp
		},
	}
	api := newFakeAPI(srv)

	_, err := api.GetCertificate(context.Background(), fakeVaultURL, "api", "v7")
	assertProblem(t, err, ErrorUnreachable, 0)
	if strings.Contains(err.Error(), body) || strings.Contains(err.Error(), "fake-access-token") {
		t.Fatalf("raw SDK error text leaked: %q", err.Error())
	}
}

func TestClientReportsCancellationBeforeCall(t *testing.T) {
	srv := &azcertfake.Server{}
	api := newFakeAPIWithTransport(canceledGuardTransport{inner: azcertfake.NewServerTransport(srv)})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := api.ListCertificateProperties(ctx, fakeVaultURL, "")
	assertProblem(t, err, ErrorCanceled, 0)

	_, err = api.GetCertificate(ctx, fakeVaultURL, "api", "v7")
	assertProblem(t, err, ErrorCanceled, 0)

	_, err = api.GetCertificatePolicy(ctx, fakeVaultURL, "api", "v7")
	assertProblem(t, err, ErrorCanceled, 0)
}

func TestSourceScanUsesOnlyAllowedOperations(t *testing.T) {
	apiDER := testCertificateDER(t, "api.example.com")
	webDER := testCertificateDER(t, "web.example.com")
	apiID := azcertificates.ID(fakeVaultURL + "/certificates/api")
	webID := azcertificates.ID(fakeVaultURL + "/certificates/web/v7")
	certificates := map[string][]byte{"api": apiDER, "web": webDER}

	var mu sync.Mutex
	calls := map[string]int{}
	record := func(operation string) {
		mu.Lock()
		defer mu.Unlock()
		calls[operation]++
	}

	pager := azfake.PagerResponder[azcertificates.ListCertificatePropertiesResponse]{}
	pager.AddPage(http.StatusOK, azcertificates.ListCertificatePropertiesResponse{
		CertificatePropertiesListResult: azcertificates.CertificatePropertiesListResult{
			Value: []*azcertificates.CertificateProperties{{ID: &apiID}, {ID: &webID}},
		},
	}, nil)

	srv := &azcertfake.Server{
		NewListCertificatePropertiesPager: func(_ *azcertificates.ListCertificatePropertiesOptions) azfake.PagerResponder[azcertificates.ListCertificatePropertiesResponse] {
			record("ListCertificateProperties")
			return pager
		},
		GetCertificate: func(_ context.Context, name string, version string, _ *azcertificates.GetCertificateOptions) (azfake.Responder[azcertificates.GetCertificateResponse], azfake.ErrorResponder) {
			record("GetCertificate")
			// The SDK fake splits the request path with a character class that
			// includes the slash, so it hands over the whole path suffix as the
			// name and leaves the version empty.
			name = strings.TrimSuffix(name, "/")
			if base, found, ok := strings.Cut(name, "/"); ok {
				name, version = base, found
			}
			der, ok := certificates[name]
			if !ok {
				t.Errorf("unexpected certificate %q", name)
			}
			id := azcertificates.ID(fakeVaultURL + "/certificates/" + name)
			if version != "" {
				id = azcertificates.ID(fakeVaultURL + "/certificates/" + name + "/" + version)
			}
			resp := azfake.Responder[azcertificates.GetCertificateResponse]{}
			resp.SetResponse(http.StatusOK, azcertificates.GetCertificateResponse{
				Certificate: azcertificates.Certificate{ID: &id, CER: der},
			}, nil)
			return resp, azfake.ErrorResponder{}
		},
		GetCertificatePolicy: func(_ context.Context, _ string, _ *azcertificates.GetCertificatePolicyOptions) (azfake.Responder[azcertificates.GetCertificatePolicyResponse], azfake.ErrorResponder) {
			record("GetCertificatePolicy")
			issuer := "DigiCert"
			months := int32(3)
			resp := azfake.Responder[azcertificates.GetCertificatePolicyResponse]{}
			resp.SetResponse(http.StatusOK, azcertificates.GetCertificatePolicyResponse{
				CertificatePolicy: azcertificates.CertificatePolicy{
					IssuerParameters:          &azcertificates.IssuerParameters{Name: &issuer},
					X509CertificateProperties: &azcertificates.X509CertificateProperties{ValidityInMonths: &months},
				},
			}, nil)
			return resp, azfake.ErrorResponder{}
		},
	}
	assertOnlyAllowedOperations(t, srv)

	owners, err := owner.ParseConfig(nil)
	if err != nil {
		t.Fatalf("parse owners: %v", err)
	}
	api := newFakeAPI(srv)
	source, err := NewSource(api, LoadOptions{VaultURLs: []string{fakeVaultURL}, QPS: 100000, Owners: owners})
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	got, problems, err := source.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(problems) != 0 {
		t.Fatalf("problems = %+v", problems)
	}
	if len(got) != 2 {
		t.Fatalf("certificates = %d, want 2", len(got))
	}
	for _, certificate := range got {
		der, ok := certificates[certificate.Facts.Name]
		if !ok {
			t.Fatalf("unexpected certificate %q", certificate.Facts.Name)
		}
		sum := sha256.Sum256(der)
		if want := hex.EncodeToString(sum[:]); certificate.Fingerprint != want {
			t.Fatalf("fingerprint = %q, want %q", certificate.Fingerprint, want)
		}
	}
	if got[0].Facts.Version != "" || got[1].Facts.Version != "v7" {
		t.Fatalf("versions = %q,%q", got[0].Facts.Version, got[1].Facts.Version)
	}
	mu.Lock()
	defer mu.Unlock()
	want := map[string]int{
		"ListCertificateProperties": 1,
		"GetCertificate":            2,
		"GetCertificatePolicy":      2,
	}
	if diff := cmp.Diff(want, calls); diff != "" {
		t.Fatalf("operation counts mismatch (-want +got):\n%s", diff)
	}
}

// assertOnlyAllowedOperations proves that every other fake server operation
// stays nil so the scan can only use list, get certificate, and get policy.
func assertOnlyAllowedOperations(t *testing.T, srv *azcertfake.Server) {
	t.Helper()
	allowed := map[string]bool{
		"NewListCertificatePropertiesPager": true,
		"GetCertificate":                    true,
		"GetCertificatePolicy":              true,
	}
	value := reflect.ValueOf(*srv)
	for index := 0; index < value.NumField(); index++ {
		name := value.Type().Field(index).Name
		if allowed[name] {
			continue
		}
		if !value.Field(index).IsNil() {
			t.Fatalf("fake server operation %q must stay nil", name)
		}
	}
}
