package azurekv

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fuzzCertificateDER returns a self-signed certificate for the seed corpus.
func fuzzCertificateDER(t testing.TB) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(4096),
		Subject:      pkix.Name{CommonName: "fuzz.example.com"},
		DNSNames:     []string{"fuzz.example.com"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

// certificateIDSegments returns the path segments of a certificate ID as the
// parser sees them, so a test can tell the two segment form from the three
// segment form without repeating the split itself.
func certificateIDSegments(id string) []string {
	parsed, err := url.Parse(id)
	if err != nil {
		return nil
	}
	return strings.Split(strings.Trim(parsed.Path, "/"), "/")
}

func FuzzSplitCertificateID(f *testing.F) {
	for _, seed := range []string{
		"https://demo.vault.azure.net/certificates/api/v1",
		"https://demo.vault.azure.net/certificates/api",
		"",
		"https://demo.vault.azure.net/certificates/api/",
		"https://demo.vault.azure.net/certificates/api/v1/",
		"https://demo.vault.azure.net/certificates/api/v1/extra",
		"https://demo.vault.azure.net/keys/api",
		"https://demo.vault.azure.net/secrets/api",
		"https://demo.vault.azure.net/certificates/api%2Fv1",
		"https://demo.vault.azure.net/certificates/" + strings.Repeat("n", 4096),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, id string) {
		name, version, ok := splitCertificateID(id)
		if !ok {
			return
		}
		if name == "" {
			t.Fatalf("accepted an empty certificate name for %q", id)
		}
		if strings.Contains(name, "/") || strings.Contains(version, "/") {
			t.Fatalf("accepted a slash in the name or the version for %q: name=%q version=%q", id, name, version)
		}
		switch segments := certificateIDSegments(id); len(segments) {
		case 2:
			if version != "" {
				t.Fatalf("version %q for the two segment form of %q", version, id)
			}
		case 3:
			if version == "" {
				t.Fatalf("empty version for the three segment form of %q", id)
			}
		default:
			t.Fatalf("accepted %q with %d path segments", id, len(segments))
		}
	})
}

func FuzzParseCertificate(f *testing.F) {
	der := fuzzCertificateDER(f)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	f.Add(der)
	f.Add(encoded)
	f.Add([]byte{})
	f.Add(der[:len(der)/2])
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"))
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	f.Fuzz(func(t *testing.T, data []byte) {
		certificate, err := parseCertificate(data)
		if certificate != nil && err != nil {
			t.Fatalf("certificate and error for %d bytes of input", len(data))
		}
		if certificate == nil && err == nil {
			t.Fatalf("no certificate and no error for %d bytes of input", len(data))
		}
	})
}

func FuzzValidateVaultURL(f *testing.F) {
	for _, seed := range []string{
		"https://demo.vault.azure.net",
		"https://demo.vault.azure.net/",
		"http://demo.vault.azure.net",
		"https://user@demo.vault.azure.net",
		"https://demo.vault.azure.net/path",
		"https://demo.vault.azure.net?query=1",
		"https://demo.vault.azure.net#fragment",
		"not a url",
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if err := ValidateVaultURL(raw); err != nil {
			return
		}
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			t.Fatalf("accepted %q that does not parse: %v", raw, err)
		}
		if parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "" ||
			parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
			t.Fatalf("accepted %q: scheme=%q host=%q path=%q query=%q fragment=%q user=%v",
				raw, parsed.Scheme, parsed.Host, parsed.Path, parsed.RawQuery, parsed.Fragment, parsed.User)
		}
		if host := vaultHost(raw); host != parsed.Host {
			t.Fatalf("vaultHost(%q) = %q but the accepted vault host is %q", raw, host, parsed.Host)
		}
	})
}
