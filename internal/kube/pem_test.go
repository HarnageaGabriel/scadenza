package kube

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestParseChainIgnoresNonCertificateBlocks(t *testing.T) {
	leaf := generateCertificate(t, "leaf.example.com", nil)
	ca := generateCertificate(t, "ca.example.com", nil)
	payload := strings.Join([]string{
		"-----BEGIN PRIVATE KEY-----\nSUPERSECRETKEYMATERIAL\n-----END PRIVATE KEY-----",
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})),
		"-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----",
		string(pem.EncodeToMemory(&pem.Block{Type: "certificate", Bytes: ca.Raw})),
	}, "\n")
	chain, err := ParseChain([]byte(payload))
	if err != nil {
		t.Fatalf("ParseChain: %v", err)
	}
	if len(chain.Der) != 2 || chain.Leaf == nil {
		t.Fatalf("chain = %d certificates", len(chain.Der))
	}
	if Fingerprint(chain.Leaf.Raw) != Fingerprint(leaf.Raw) {
		t.Fatalf("leaf fingerprint does not match the first certificate block")
	}
	if strings.Contains(payload, "SUPERSECRETKEYMATERIAL") && containsAny(chain.Der) {
		t.Fatalf("key material leaked into the parsed chain")
	}
}

func containsAny(blobs [][]byte) bool {
	for _, blob := range blobs {
		if strings.Contains(string(blob), "SUPERSECRETKEYMATERIAL") {
			return true
		}
	}
	return false
}

func TestParseChainFailures(t *testing.T) {
	for name, payload := range map[string]string{
		"empty":                 "",
		"not pem at all":        "not a certificate",
		"key only":              "-----BEGIN PRIVATE KEY-----\nSUPERSECRETKEYMATERIAL\n-----END PRIVATE KEY-----",
		"broken certificate":    "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----",
		"truncated pem":         "-----BEGIN CERTIFICATE-----\n",
		"unknown block only":    "-----BEGIN SOMETHING-----\naGk=\n-----END SOMETHING-----",
		"valid base64 not cert": "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseChain([]byte(payload)); err == nil {
				t.Fatalf("ParseChain(%q) = nil error", payload)
			}
		})
	}
}

func TestNamesAndSerial(t *testing.T) {
	leaf := generateCertificate(t, "leaf.example.com", []string{"b.example.com", "a.example.com", "A.example.com"})
	names := Names(leaf)
	if len(names) != 2 || names[0] != "a.example.com" || names[1] != "b.example.com" {
		t.Fatalf("names = %v", names)
	}
	if got := Serial(leaf); got == "" || strings.ToLower(got) != got {
		t.Fatalf("serial = %q", got)
	}
	commonName := &x509.Certificate{Subject: leaf.Subject}
	commonName.Subject.CommonName = "only.example.com"
	if got := Names(commonName); len(got) != 1 || got[0] != "only.example.com" {
		t.Fatalf("common-name fallback = %v", got)
	}
}

func FuzzParseChain(f *testing.F) {
	for _, seed := range []string{
		"",
		"-----BEGIN CERTIFICATE-----\n",
		"-----BEGIN CERTIFICATE-----\naGk=\n-----END CERTIFICATE-----\n",
		"random",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, payload string) {
		chain, err := ParseChain([]byte(payload))
		if err != nil {
			return
		}
		if chain.Leaf == nil || len(chain.Der) == 0 {
			t.Fatalf("successful parse without a leaf for %q", payload)
		}
		if Fingerprint(chain.Leaf.Raw) != Fingerprint(chain.Der[0]) {
			t.Fatalf("leaf is not the first parsed certificate for %q", payload)
		}
	})
}
