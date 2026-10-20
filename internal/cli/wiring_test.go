package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/HarnageaGabriel/scadenza/internal/clock"
	"github.com/HarnageaGabriel/scadenza/internal/ct"
	"github.com/HarnageaGabriel/scadenza/internal/inventory"
	"github.com/HarnageaGabriel/scadenza/internal/tlsprobe"
)

// fakeCTSource is a scripted Certificate Transparency source. It implements
// ct.TruncatingSource, so the scan learns that a result stopped at the entry
// cap.
type fakeCTSource struct {
	name         string
	certificates []ct.Certificate
	truncated    bool
	err          error
}

func (s *fakeCTSource) Name() string { return s.name }

func (s *fakeCTSource) Search(context.Context, ct.Query) ([]ct.Certificate, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.certificates, nil
}

func (s *fakeCTSource) SearchResult(context.Context, ct.Query) (ct.Result, error) {
	if s.err != nil {
		return ct.Result{}, s.err
	}
	return ct.Result{Certificates: s.certificates, Truncated: s.truncated}, nil
}

// fakeResolver resolves the scripted host names and fails for every other
// name, so a probe never touches DNS.
type fakeResolver struct {
	addresses map[string]string
}

func (r fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	address, ok := r.addresses[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return []net.IPAddr{{IP: net.ParseIP(address)}}, nil
}

// recordingDialer records every address it is asked to dial and refuses the
// connection, so a test can prove which addresses were reached.
type recordingDialer struct {
	mutex  sync.Mutex
	dialed []string
}

func (d *recordingDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.dialed = append(d.dialed, address)
	return nil, errors.New("connection refused by the test")
}

func (d *recordingDialer) addresses() []string {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return append([]string{}, d.dialed...)
}

// ctRecord builds one Certificate Transparency record for the given names.
func ctRecord(names ...string) ct.Certificate {
	return ct.Certificate{
		Fingerprint:  strings.Repeat("a", 64),
		SubjectNames: names,
		Issuer:       "CN=Example Root",
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		Source:       "certspotter",
		DedupKey:     "1",
	}
}

// wiringDependencies wires one scripted source and one prober into the scan.
func wiringDependencies(source ct.Source, prober hostProber) ctDependencies {
	dependencies := scanDependencies("http://127.0.0.1:1", prober)
	dependencies.clock = clock.Fixed{Time: testNowScan}
	dependencies.sources = map[string]ct.Source{"certspotter": source}
	return dependencies
}

// scanDocument is the part of the scan document these tests read.
type scanDocument struct {
	ProbeErrors []inventory.ProbeError `json:"probe_errors"`
	Unresolved  []inventory.Unresolved `json:"unresolved"`
	Coverage    inventory.Coverage     `json:"coverage"`
	Diagnostics []struct {
		Code string `json:"code"`
	} `json:"diagnostics"`
}

func decodeScanDocument(t *testing.T, data []byte) scanDocument {
	t.Helper()
	var document scanDocument
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode scan document: %v\n%s", err, data)
	}
	return document
}

func probeErrorClass(document scanDocument, host string) string {
	for _, probeError := range document.ProbeErrors {
		if probeError.Host == host {
			return probeError.Class
		}
	}
	return ""
}

func unresolvedReason(document scanDocument, name string) string {
	for _, entry := range document.Unresolved {
		if entry.Name == name {
			return entry.Reason
		}
	}
	return ""
}

func hasDiagnostic(document scanDocument, code string) bool {
	for _, item := range document.Diagnostics {
		if item.Code == code {
			return true
		}
	}
	return false
}

// TestScanGuardsOnlyCertificateTransparencyHosts proves that a host that came
// from Certificate Transparency is probed with the special-address guard,
// while a host the operator names is not restricted.
func TestScanGuardsOnlyCertificateTransparencyHosts(t *testing.T) {
	cases := []struct {
		name         string
		ctName       string
		address      string
		explicitHost bool
		wantBlocked  bool
	}{
		{name: "loopback address is refused", ctName: "loop.example.com", address: "127.0.0.1", wantBlocked: true},
		{name: "cloud metadata address is refused", ctName: "meta.example.com", address: "169.254.169.254", wantBlocked: true},
		{name: "private address is still probed", ctName: "int.example.com", address: "10.1.2.3"},
		{name: "a host the operator names is not restricted", ctName: "loop.example.com", address: "127.0.0.1", explicitHost: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			resolver := fakeResolver{addresses: map[string]string{
				"example.com": "192.0.2.1",
				test.ctName:   test.address,
			}}
			dialer := &recordingDialer{}
			prober := &tlsprobe.Prober{Timeout: 3 * time.Second, Clock: clock.Fixed{Time: testNowScan}, Resolver: resolver, Dialer: dialer}
			source := &fakeCTSource{name: "certspotter", certificates: []ct.Certificate{ctRecord(test.ctName)}}
			args := []string{"scan", "--domain", "example.com", "--source", "certspotter", "--format", "json"}
			if test.explicitHost {
				args = append(args, "--host", test.ctName)
			}
			var stdout, stderr bytes.Buffer
			if code := execute(context.Background(), args, &stdout, &stderr, wiringDependencies(source, prober)); code != ExitOK {
				t.Fatalf("exit = %d; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			document := decodeScanDocument(t, stdout.Bytes())
			class := probeErrorClass(document, test.ctName)
			if test.wantBlocked {
				if class != string(tlsprobe.ClassBlockedAddress) {
					t.Fatalf("probe class = %q, want %q; probe_errors=%v", class, tlsprobe.ClassBlockedAddress, document.ProbeErrors)
				}
			} else if class == string(tlsprobe.ClassBlockedAddress) {
				t.Fatalf("probe class = %q, want no blocked address; probe_errors=%v", class, document.ProbeErrors)
			}
			// The blocked host is a probe failure, never a silent drop.
			if unresolvedReason(document, test.ctName) != "" {
				t.Fatalf("blocked host was reported as unresolved: %v", document.Unresolved)
			}
			if document.Coverage.TargetsFailed != len(document.ProbeErrors) || document.Coverage.TargetsFailed == 0 {
				t.Fatalf("coverage = %+v; probe_errors=%v", document.Coverage, document.ProbeErrors)
			}
			want := net.JoinHostPort(test.address, "443")
			dialed := dialer.addresses()
			switch {
			case test.wantBlocked && containsAddress(dialed, want):
				t.Fatalf("%s must not be dialed; dialed=%v", want, dialed)
			case !test.wantBlocked && !containsAddress(dialed, want):
				t.Fatalf("%s must be dialed; dialed=%v", want, dialed)
			}
		})
	}
}

func containsAddress(addresses []string, want string) bool {
	for _, address := range addresses {
		if address == want {
			return true
		}
	}
	return false
}

// TestScanDoesNotProbeInvalidCertificateTransparencyNames proves that a name
// that fails the host name validation is never probed and is reported as not
// checked, without the raw bytes of the name.
func TestScanDoesNotProbeInvalidCertificateTransparencyNames(t *testing.T) {
	cases := []struct {
		name   string
		ctName string
	}{
		{name: "newline", ctName: "bad\nname.example.com"},
		{name: "escape sequence", ctName: "bad\x1b[31m.example.com"},
		{name: "space", ctName: "bad name.example.com"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			resolver := fakeResolver{addresses: map[string]string{
				"example.com": "192.0.2.1",
				test.ctName:   "198.51.100.7",
			}}
			dialer := &recordingDialer{}
			prober := &tlsprobe.Prober{Timeout: 3 * time.Second, Clock: clock.Fixed{Time: testNowScan}, Resolver: resolver, Dialer: dialer}
			source := &fakeCTSource{name: "certspotter", certificates: []ct.Certificate{ctRecord(test.ctName)}}
			var stdout, stderr bytes.Buffer
			if code := execute(context.Background(), []string{"scan", "--domain", "example.com", "--source", "certspotter", "--format", "json"},
				&stdout, &stderr, wiringDependencies(source, prober)); code != ExitOK {
				t.Fatalf("exit = %d; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			document := decodeScanDocument(t, stdout.Bytes())
			if containsAddress(dialer.addresses(), "198.51.100.7:443") {
				t.Fatalf("the invalid name was dialed: %v", dialer.addresses())
			}
			for _, probeError := range document.ProbeErrors {
				if strings.Contains(probeError.Host, "bad") {
					t.Fatalf("the invalid name was probed: %v", document.ProbeErrors)
				}
			}
			invalid := []inventory.Unresolved{}
			for _, entry := range document.Unresolved {
				if entry.Reason == reasonInvalidName {
					invalid = append(invalid, entry)
				}
			}
			if len(invalid) != 1 {
				t.Fatalf("the invalid name was not reported as not checked: %v", document.Unresolved)
			}
			assertNoControlRunes(t, invalid[0].Name)
			assertNoControlRunes(t, invalid[0].Detail)
			if document.Coverage.NamesNotChecked == 0 {
				t.Fatalf("the invalid name was not counted as not checked: %+v", document.Coverage)
			}
			if strings.Contains(stdout.String(), "\x1b") {
				t.Fatalf("the output carries a raw escape byte: %q", stdout.String())
			}
			for _, r := range stderr.String() {
				if unicode.IsControl(r) && r != '\n' {
					t.Fatalf("stderr carries a raw control byte %U: %q", r, stderr.String())
				}
			}
		})
	}
}

func assertNoControlRunes(t *testing.T, value string) {
	t.Helper()
	for _, r := range value {
		if unicode.IsControl(r) {
			t.Errorf("value carries the control character %U: %q", r, value)
		}
	}
}

// TestScanReportsTruncatedCertificateTransparencyResult proves that a result
// that stopped at the entry cap marks the source as partial and fails a
// strict scan, while an untruncated result stays unchanged.
func TestScanReportsTruncatedCertificateTransparencyResult(t *testing.T) {
	cases := []struct {
		name       string
		truncated  bool
		wantStatus string
		wantExit   int
		wantCode   bool
	}{
		{name: "truncated result is partial", truncated: true, wantStatus: inventory.SourceStatusPartial, wantExit: ExitIncompleteScan, wantCode: true},
		{name: "untruncated result is unchanged", truncated: false, wantStatus: inventory.SourceStatusOK, wantExit: ExitOK},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			leaf := selfSignedLeaf(t, []string{"example.com"}, 90*24*time.Hour)
			port := serveTLS(t, leaf)
			resolver := fakeResolver{addresses: map[string]string{"example.com": "127.0.0.1"}}
			prober := &tlsprobe.Prober{Timeout: 3 * time.Second, Clock: clock.Fixed{Time: testNowScan}, Resolver: resolver}
			source := &fakeCTSource{name: "certspotter", certificates: []ct.Certificate{ctRecord("example.com")}, truncated: test.truncated}
			var stdout, stderr bytes.Buffer
			code := execute(context.Background(), []string{
				"scan", "--domain", "example.com", "--source", "certspotter",
				"--port", strconv.Itoa(port), "--fail-on", "none", "--strict", "--format", "json",
			}, &stdout, &stderr, wiringDependencies(source, prober))
			if code != test.wantExit {
				t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, test.wantExit, stdout.String(), stderr.String())
			}
			document := decodeScanDocument(t, stdout.Bytes())
			sources := sourceCoverage(stdout.Bytes())
			certspotter := sources["certspotter"]
			if certspotter.Status != test.wantStatus {
				t.Fatalf("certspotter = %+v, want status %s", certspotter, test.wantStatus)
			}
			if test.truncated && !strings.Contains(certspotter.Detail, "entry cap") {
				t.Fatalf("certspotter detail = %q, want the entry cap", certspotter.Detail)
			}
			if hasDiagnostic(document, "SCD-0034") != test.wantCode {
				t.Fatalf("SCD-0034 present = %v, want %v", hasDiagnostic(document, "SCD-0034"), test.wantCode)
			}
			if strings.Contains(stderr.String(), "SCD-0034") != test.wantCode {
				t.Fatalf("stderr = %q", stderr.String())
			}
		})
	}
}
