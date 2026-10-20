package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/ct"
	"github.com/HarnageaGabriel/scadenza/internal/inventory"
	"github.com/HarnageaGabriel/scadenza/internal/tlsprobe"
)

// slowCTSource answers every query after a short delay, so a test can let a
// deadline cut a run short while the same source still answers when the limit
// is longer than the delay.
type slowCTSource struct {
	delay        time.Duration
	certificates []ct.Certificate
}

func (source *slowCTSource) Name() string { return "certspotter" }

func (source *slowCTSource) Search(ctx context.Context, _ ct.Query) ([]ct.Certificate, error) {
	timer := time.NewTimer(source.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return source.certificates, nil
	}
}

// cutShortCTSource answers the first query and blocks on the next one until
// its context is done. The source therefore produced data and did not finish,
// which is what the coverage reports as a partial source.
type cutShortCTSource struct {
	certificates []ct.Certificate
	mutex        sync.Mutex
	queries      int
}

func (source *cutShortCTSource) Name() string { return "certspotter" }

func (source *cutShortCTSource) Search(ctx context.Context, _ ct.Query) ([]ct.Certificate, error) {
	source.mutex.Lock()
	source.queries++
	first := source.queries == 1
	source.mutex.Unlock()
	if first {
		return source.certificates, nil
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

// fastProber answers every probe at once, so the only slow part of the run is
// the Certificate Transparency work the deadline cuts short.
type fastProber struct {
	result tlsprobe.Result
}

func (prober fastProber) Probe(_ context.Context, host string, port int, _ string) (tlsprobe.Result, error) {
	result := prober.result
	result.Host, result.Port = host, port
	return result, nil
}

// deadlineLines returns the stderr lines that report the given code.
func deadlineLines(stderr string, code string) []string {
	result := []string{}
	for _, line := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(line, code+" ") {
			result = append(result, line)
		}
	}
	return result
}

// TestScanDeadlineRendersWhatWasCollected proves that a run that reaches its
// maximum duration still reports what it collected: the document is written,
// the source that was cut short is partial, the deadline is reported once,
// and the exit code follows the ordinary rules.
func TestScanDeadlineRendersWhatWasCollected(t *testing.T) {
	// Every run gets a fresh source: the source answers its first query and
	// blocks on the next one.
	dependencies := func() ctDependencies {
		source := &cutShortCTSource{certificates: []ct.Certificate{ctRecord("a.example.com")}}
		return wiringDependencies(source, fastProber{result: tlsprobe.Result{
			Fingerprint: strings.Repeat("a", 64),
			Serial:      "0a",
			Names:       []string{"a.example.com"},
			Issuer:      "CN=Example Root",
			NotBefore:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:    time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
			Trusted:     true,
		}})
	}
	args := []string{
		"scan", "--domain", "a.example.com", "--domain", "b.example.com",
		"--source", "certspotter", "--max-duration", "50ms", "--format", "json",
	}

	var stdout, stderr bytes.Buffer
	code := execute(context.Background(), args, &stdout, &stderr, dependencies())
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitOK, stdout.String(), stderr.String())
	}
	document := decodeScanDocument(t, stdout.Bytes())
	if !strings.Contains(stdout.String(), `"schema_version":"scadenza.scan/v1"`) {
		t.Fatalf("the run reported no document: %s", stdout.String())
	}
	coverage := sourceCoverage(stdout.Bytes())
	if coverage["certspotter"].Status != inventory.SourceStatusPartial {
		t.Fatalf("certspotter coverage = %+v, want status %s", coverage["certspotter"], inventory.SourceStatusPartial)
	}
	if !strings.Contains(coverage["certspotter"].Detail, "the run stopped at the 50ms limit") {
		t.Fatalf("certspotter detail = %q, want the deadline reason", coverage["certspotter"].Detail)
	}
	if !hasDiagnostic(document, "SCD-0035") {
		t.Fatalf("the document does not carry SCD-0035: %+v", document.Diagnostics)
	}
	lines := deadlineLines(stderr.String(), "SCD-0035")
	if len(lines) != 1 {
		t.Fatalf("stderr reported the deadline %d times: %s", len(lines), stderr.String())
	}
	want := "SCD-0035 [warning] Run reached the maximum duration: the scan stopped after 50ms"
	if lines[0] != want {
		t.Fatalf("deadline line = %q, want %q", lines[0], want)
	}
	// The source that was cut short is not reported as an unavailable source
	// as well: the deadline says why it did not answer.
	if strings.Contains(stderr.String(), "SCD-0002") {
		t.Fatalf("the cut-short source was reported as unavailable: %s", stderr.String())
	}

	// The same run with --strict is an incomplete scan, so it exits 5.
	stdout.Reset()
	stderr.Reset()
	code = execute(context.Background(), append(args, "--strict"), &stdout, &stderr, dependencies())
	if code != ExitIncompleteScan {
		t.Fatalf("exit with --strict = %d, want %d; stdout=%s stderr=%s", code, ExitIncompleteScan, stdout.String(), stderr.String())
	}
	if len(deadlineLines(stderr.String(), "SCD-0035")) != 1 {
		t.Fatalf("stderr reported the deadline more than once: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "SCD-0020") {
		t.Fatalf("the incomplete scan was not reported: %s", stderr.String())
	}
}

// TestScanDeadlineWithNothingCollectedExitsFour proves that a deadline in
// which every requested source produced nothing is the existing unavailable
// source case, so the run exits 4 and not 0.
func TestScanDeadlineWithNothingCollectedExitsFour(t *testing.T) {
	source := &slowCTSource{delay: 500 * time.Millisecond}
	dependencies := wiringDependencies(source, fakeProber{})
	var stdout, stderr bytes.Buffer
	code := execute(context.Background(), []string{
		"scan", "--domain", "example.com", "--source", "certspotter",
		"--max-duration", "50ms", "--format", "json",
	}, &stdout, &stderr, dependencies)
	if code != ExitSourceUnavailable {
		t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitSourceUnavailable, stdout.String(), stderr.String())
	}
	if len(deadlineLines(stderr.String(), "SCD-0035")) != 1 {
		t.Fatalf("stderr did not report the deadline once: %s", stderr.String())
	}
}

// TestScanDeadlineDoesNotBeatAnInterrupt proves that an interrupt still wins
// when a deadline is configured: the run exits 130 and writes no document.
func TestScanDeadlineDoesNotBeatAnInterrupt(t *testing.T) {
	source := &blockingCTSource{started: make(chan struct{}, 1)}
	dependencies := wiringDependencies(source, fakeProber{})
	ctx, cancel := context.WithCancelCause(context.Background())
	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- execute(ctx, []string{
			"scan", "--domain", "example.com", "--source", "certspotter",
			"--max-duration", "10m", "--format", "json",
		}, &stdout, &stderr, dependencies)
	}()
	<-source.started
	cancel(ErrInterrupted)
	code := <-done
	if code != ExitInterrupted {
		t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitInterrupted, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("the interrupted run reported a result: %s", stdout.String())
	}
	if stderr.String() != interruptedMessage+"\n" {
		t.Fatalf("stderr = %q, want the single line %q", stderr.String(), interruptedMessage)
	}
}

// TestCTDeadlineDoesNotBeatAnInterrupt proves the same for the ct command.
func TestCTDeadlineDoesNotBeatAnInterrupt(t *testing.T) {
	source := &blockingCTSource{started: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancelCause(context.Background())
	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- execute(ctx, []string{
			"ct", "example.com", "--source", "certspotter", "--max-duration", "10m", "--format", "json",
		}, &stdout, &stderr, interruptDependencies(source))
	}()
	<-source.started
	cancel(ErrInterrupted)
	code := <-done
	if code != ExitInterrupted {
		t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitInterrupted, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("the interrupted run reported a result: %s", stdout.String())
	}
	if stderr.String() != interruptedMessage+"\n" {
		t.Fatalf("stderr = %q, want the single line %q", stderr.String(), interruptedMessage)
	}
}

// TestCTDeadlineReportsTheLookup proves that the ct command reports the
// deadline once and exits 4, because no source produced data.
func TestCTDeadlineReportsTheLookup(t *testing.T) {
	source := &slowCTSource{delay: 500 * time.Millisecond}
	var stdout, stderr bytes.Buffer
	code := execute(context.Background(), []string{
		"ct", "example.com", "--source", "certspotter", "--max-duration", "50ms", "--format", "json",
	}, &stdout, &stderr, interruptDependencies(source))
	if code != ExitSourceUnavailable {
		t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitSourceUnavailable, stdout.String(), stderr.String())
	}
	lines := deadlineLines(stderr.String(), "SCD-0035")
	if len(lines) != 1 {
		t.Fatalf("stderr reported the deadline %d times: %s", len(lines), stderr.String())
	}
	want := "SCD-0035 [warning] Run reached the maximum duration: the Certificate Transparency lookup stopped after 50ms"
	if lines[0] != want {
		t.Fatalf("deadline line = %q, want %q", lines[0], want)
	}
	if stdout.Len() != 0 {
		t.Fatalf("the lookup reported a result: %s", stdout.String())
	}
}

// TestMaxDurationZeroKeepsTheRunUnchanged proves that a limit of zero means
// no limit: the run behaves exactly as it does without the option.
func TestMaxDurationZeroKeepsTheRunUnchanged(t *testing.T) {
	t.Run("the scan command", func(t *testing.T) {
		dependencies := wiringDependencies(scanSource(true), matchedProber())
		var stdout, stderr bytes.Buffer
		code := execute(context.Background(), []string{
			"scan", "--domain", "example.com", "--source", "certspotter", "--max-duration", "0", "--format", "json",
		}, &stdout, &stderr, dependencies)
		if code != ExitOK {
			t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitOK, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), `"schema_version":"scadenza.scan/v1"`) {
			t.Fatalf("the run reported no document: %s", stdout.String())
		}
		if strings.Contains(stderr.String(), "SCD-0035") {
			t.Fatalf("the run reported a deadline: %s", stderr.String())
		}
	})

	t.Run("the ct command", func(t *testing.T) {
		source := &fakeCTSource{name: "certspotter", certificates: []ct.Certificate{ctRecord("example.com")}}
		var stdout, stderr bytes.Buffer
		code := execute(context.Background(), []string{
			"ct", "example.com", "--source", "certspotter", "--max-duration", "0", "--format", "json",
		}, &stdout, &stderr, interruptDependencies(source))
		if code != ExitOK {
			t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitOK, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), `"schema_version":"scadenza.ct/v1"`) {
			t.Fatalf("the run reported no document: %s", stdout.String())
		}
		if strings.Contains(stderr.String(), "SCD-0035") {
			t.Fatalf("the run reported a deadline: %s", stderr.String())
		}
	})
}

// TestMaxDurationRejectsANegativeValue proves that a negative limit is a
// usage error, on both commands.
func TestMaxDurationRejectsANegativeValue(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "--domain", "example.com", "--max-duration", "-1s"},
		{"ct", "example.com", "--max-duration", "-1s"},
	} {
		var stdout, stderr bytes.Buffer
		code := execute(context.Background(), args, &stdout, &stderr, interruptDependencies(scanSource(true)))
		if code != ExitUsageError {
			t.Fatalf("args=%v exit = %d, want %d", args, code, ExitUsageError)
		}
		if !strings.Contains(stderr.String(), "SCD-0001") {
			t.Fatalf("args=%v stderr = %q, want the usage diagnostic", args, stderr.String())
		}
		if stdout.Len() != 0 {
			t.Fatalf("args=%v reported a result: %s", args, stdout.String())
		}
	}
}

// TestMaxDurationFromTheConfigurationFile proves that the configuration file
// sets the limit and that the command line wins over the file.
func TestMaxDurationFromTheConfigurationFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scadenza.yaml")
	document := "version: 1\ndomains:\n  - example.com\nmaxDuration: 50ms\n"
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{
		"scan", "--source", "certspotter", "--config", path, "--format", "json",
	}

	// The file sets the limit, so the slow source is cut short.
	var stdout, stderr bytes.Buffer
	code := execute(context.Background(), args, &stdout, &stderr,
		wiringDependencies(&slowCTSource{delay: 500 * time.Millisecond}, fakeProber{}))
	if len(deadlineLines(stderr.String(), "SCD-0035")) != 1 {
		t.Fatalf("the configured limit did not stop the run: %s", stderr.String())
	}
	if code != ExitSourceUnavailable {
		t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitSourceUnavailable, stdout.String(), stderr.String())
	}

	// The command line wins over the file, so the same file with a longer
	// limit lets the source answer.
	stdout.Reset()
	stderr.Reset()
	code = execute(context.Background(), append(args, "--max-duration", "10m"), &stdout, &stderr,
		wiringDependencies(&slowCTSource{delay: 100 * time.Millisecond, certificates: []ct.Certificate{ctRecord("example.com")}}, matchedProber()))
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitOK, stdout.String(), stderr.String())
	}
	if strings.Contains(stderr.String(), "SCD-0035") {
		t.Fatalf("the command line did not win over the file: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), `"schema_version":"scadenza.scan/v1"`) {
		t.Fatalf("the run reported no document: %s", stdout.String())
	}
}
