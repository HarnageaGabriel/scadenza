package kube

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"iter"
	"sort"
	"strings"
)

// errNoCertificate reports a TLS secret or PEM payload without a certificate.
var errNoCertificate = errors.New("no certificate found")

// certificates yields every CERTIFICATE block in a PEM payload in order. Blocks
// of any other type, including key material, are ignored and never decoded.
func certificates(data []byte) iter.Seq2[*x509.Certificate, error] {
	return func(yield func(*x509.Certificate, error) bool) {
		rest := data
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				return
			}
			if !strings.EqualFold(block.Type, "CERTIFICATE") {
				continue
			}
			parsed, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				yield(nil, fmt.Errorf("parse certificate block: %w", err))
				return
			}
			if !yield(parsed, nil) {
				return
			}
		}
	}
}

// Chain is a parsed PEM certificate chain. Leaf is the first CERTIFICATE block;
// Der holds every parsed certificate in file order.
type Chain struct {
	Leaf *x509.Certificate
	Der  [][]byte
}

// ParseChain parses the leaf and the certificates that follow it. Non-certificate
// PEM blocks are ignored. It fails when the payload holds no certificate or a
// certificate block cannot be parsed.
func ParseChain(data []byte) (Chain, error) {
	chain := Chain{}
	for certificate, err := range certificates(data) {
		if err != nil {
			return Chain{}, err
		}
		if chain.Leaf == nil {
			chain.Leaf = certificate
		}
		chain.Der = append(chain.Der, certificate.Raw)
	}
	if chain.Leaf == nil {
		return Chain{}, errNoCertificate
	}
	return chain, nil
}

// Fingerprint returns the SHA-256 of a DER certificate as lowercase hex, the
// same fingerprint form the rest of scadenza uses.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// Names returns the leaf DNS names, falling back to the common name when no
// subject alternative name is present. The result is sorted and deduplicated.
func Names(leaf *x509.Certificate) []string {
	names := make([]string, 0, len(leaf.DNSNames)+1)
	names = append(names, leaf.DNSNames...)
	if len(leaf.DNSNames) == 0 && leaf.Subject.CommonName != "" {
		names = append(names, leaf.Subject.CommonName)
	}
	set := map[string]bool{}
	result := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || set[name] {
			continue
		}
		set[name] = true
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

// Serial returns the lowercase hexadecimal serial number, or an empty string.
func Serial(leaf *x509.Certificate) string {
	if leaf.SerialNumber == nil {
		return ""
	}
	return strings.ToLower(leaf.SerialNumber.Text(16))
}
