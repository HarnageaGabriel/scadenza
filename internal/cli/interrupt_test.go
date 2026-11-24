package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/azurekv"
	"github.com/HarnageaGabriel/scadenza/internal/clock"
	"github.com/HarnageaGabriel/scadenza/internal/ct"
	"github.com/HarnageaGabriel/scadenza/internal/tlsprobe"
)

// blockingCTSource is a Certificate Transparency source that blocks until its
// context is done, so a test can stop the run while the source still works.
type blockingCTSource struct {
	started chan struct{}
}

func (source *blockingCTSource) Name() string { return "certspotter" }

func (source *blockingCTSource) Search(ctx context.Context, _ ct.Query) ([]ct.Certificate, error) {
	notify(source.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

// blockingProber is a prober that blocks until its context is done, so a test
// can stop the run while a handshake is still in flight.
type blockingProber struct {
	started chan struct{}
}

func (prober *blockingProber) Probe(ctx context.Context, _ string, _ int, _ string) (tlsprobe.Result, error) {
	notify(prober.started)
	<-ctx.Done()
	return tlsprobe.Result{}, ctx.Err()
}

// notify reports that the fake reached the blocking call. The channel has room
// for one value, so a second call never blocks and never panics.
func notify(started chan struct{}) {
	select {
	case started <- struct{}{}:
	default:
	}
}

// interruptDependencies wires a blocking Certificate Transparency source into
// the ct command.
func interruptDependencies(source ct.Source) ctDependencies {
	return ctDependencies{
		clock:   clock.Fixed{Time: testNowScan},
		sources: map[string]ct.Source{"certspotter": source},
	}
}

// deadlineThenInterruptSource waits for the deadline to expire, then reports
// an interrupt on the run context and still returns data, so the write path
// is reached with the deadline cause set first and the interrupt second.
type deadlineThenInterruptSource struct {
	cancelRun context.CancelCauseFunc
}

func (source *deadlineThenInterruptSource) Name() string { return "certspotter" }

func (source *deadlineThenInterruptSource) Search(ctx context.Context, _ ct.Query) ([]ct.Certificate, error) {
	<-ctx.Done()
	source.cancelRun(ErrInterrupted)
	return []ct.Certificate{ctRecord("example.com")}, nil
}

// recordingCTSource records that the command body reached the source, so a
// test can prove the body guard stopped the run before any work.
type recordingCTSource struct {
	fakeCTSource
	called bool
}

func (source *recordingCTSource) Search(ctx context.Context, query ct.Query) ([]ct.Certificate, error) {
	source.called = true
	return source.fakeCTSource.Search(ctx, query)
}

func (source *recordingCTSource) SearchResult(ctx context.Context, query ct.Query) (ct.Result, error) {
	source.called = true
	return source.fakeCTSource.SearchResult(ctx, query)
}

// TestCTInterruptedStopsTheRun proves that an interrupt stops the run at
// once: the exit code is 130, nothing is written to stdout, and the last line
// on stderr is `interrupted`.
func TestCTInterruptedStopsTheRun(t *testing.T) {
	source := &blockingCTSource{started: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancelCause(context.Background())
	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- execute(ctx, []string{"ct", "example.com", "--source", "certspotter"}, &stdout, &stderr, interruptDependencies(source))
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
	if last := lastLine(stderr.String()); last != interruptedMessage {
		t.Fatalf("stderr = %q, want the last line %q", stderr.String(), interruptedMessage)
	}
}

// TestScanInterruptedStopsTheRun proves that an interrupt during a handshake
// stops the scan the same way: exit 130, no document on stdout, and the last
// line on stderr is `interrupted`.
func TestScanInterruptedStopsTheRun(t *testing.T) {
	prober := &blockingProber{started: make(chan struct{}, 1)}
	dependencies := wiringDependencies(scanSource(true), prober)
	ctx, cancel := context.WithCancelCause(context.Background())
	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- execute(ctx, []string{"scan", "--domain", "example.com", "--source", "certspotter", "--format", "json"}, &stdout, &stderr, dependencies)
	}()
	<-prober.started
	cancel(ErrInterrupted)
	code := <-done
	if code != ExitInterrupted {
		t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitInterrupted, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("the interrupted run reported a result: %s", stdout.String())
	}
	if last := lastLine(stderr.String()); last != interruptedMessage {
		t.Fatalf("stderr = %q, want the last line %q", stderr.String(), interruptedMessage)
	}
}

// TestInterruptBeatsEveryOtherExitCode proves the documented precedence: an
// interrupted run exits 130 even when the command line was invalid, so the
// interrupt is never reported as a usage error.
func TestInterruptBeatsEveryOtherExitCode(t *testing.T) {
	source := &blockingCTSource{started: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(ErrInterrupted)
	var stdout, stderr bytes.Buffer
	code := execute(ctx, []string{"ct", "not a domain", "--source", "certspotter"}, &stdout, &stderr, interruptDependencies(source))
	if code != ExitInterrupted {
		t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitInterrupted, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), interruptedMessage) {
		t.Fatalf("stderr = %q, want the interrupt line", stderr.String())
	}
}

// TestCancellationThatIsNotAnInterruptKeepsTheExitCodes proves that a
// cancellation with another cause keeps today's behaviour: the failed source
// is still reported and the run still exits 4.
func TestCancellationThatIsNotAnInterruptKeepsTheExitCodes(t *testing.T) {
	t.Run("a cancel by the caller", func(t *testing.T) {
		source := &blockingCTSource{started: make(chan struct{}, 1)}
		ctx, cancel := context.WithCancelCause(context.Background())
		var stdout, stderr bytes.Buffer
		done := make(chan int, 1)
		go func() {
			done <- execute(ctx, []string{"ct", "example.com", "--source", "certspotter"}, &stdout, &stderr, interruptDependencies(source))
		}()
		<-source.started
		cancel(errors.New("the caller stopped the run"))
		code := <-done
		if code != ExitSourceUnavailable {
			t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitSourceUnavailable, stdout.String(), stderr.String())
		}
		if !strings.Contains(stderr.String(), "SCD-0002") {
			t.Fatalf("the failed source was not reported: %s", stderr.String())
		}
		if strings.Contains(stderr.String(), interruptedMessage) {
			t.Fatalf("a cancel that is not an interrupt reported an interrupt: %s", stderr.String())
		}
	})

	t.Run("a deadline", func(t *testing.T) {
		source := &blockingCTSource{started: make(chan struct{}, 1)}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		var stdout, stderr bytes.Buffer
		code := execute(ctx, []string{"ct", "example.com", "--source", "certspotter"}, &stdout, &stderr, interruptDependencies(source))
		if code != ExitSourceUnavailable {
			t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitSourceUnavailable, stdout.String(), stderr.String())
		}
		if strings.Contains(stderr.String(), interruptedMessage) {
			t.Fatalf("a deadline reported an interrupt: %s", stderr.String())
		}
	})
}

// TestInterruptAfterTheDeadlineStopsTheWrite proves that an interrupt on the
// run context still stops the write when the maximum duration expired first:
// the deadline cause must not hide the interrupt, so the run exits 130 and
// stdout stays empty.
func TestInterruptAfterTheDeadlineStopsTheWrite(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	source := &deadlineThenInterruptSource{cancelRun: cancel}
	var stdout, stderr bytes.Buffer
	code := execute(ctx, []string{"ct", "example.com", "--source", "certspotter", "--format", "json", "--max-duration", "1ms"}, &stdout, &stderr, interruptDependencies(source))
	if code != ExitInterrupted {
		t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitInterrupted, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("the interrupted run reported a result: %s", stdout.String())
	}
}

// TestRunWithoutAnInterruptIsUnchanged proves that a run nobody interrupted
// keeps its result and its exit code.
func TestRunWithoutAnInterruptIsUnchanged(t *testing.T) {
	t.Run("the ct command", func(t *testing.T) {
		source := &fakeCTSource{name: "certspotter", certificates: []ct.Certificate{ctRecord("example.com")}}
		var stdout, stderr bytes.Buffer
		code := execute(context.Background(), []string{"ct", "example.com", "--source", "certspotter", "--format", "json"}, &stdout, &stderr, interruptDependencies(source))
		if code != ExitOK {
			t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitOK, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), `"schema_version":"scadenza.ct/v1"`) {
			t.Fatalf("the run reported no document: %s", stdout.String())
		}
		if strings.Contains(stderr.String(), interruptedMessage) {
			t.Fatalf("the run reported an interrupt: %s", stderr.String())
		}
	})

	t.Run("the scan command", func(t *testing.T) {
		dependencies := wiringDependencies(scanSource(true), matchedProber())
		var stdout, stderr bytes.Buffer
		code := execute(context.Background(), []string{"scan", "--domain", "example.com", "--source", "certspotter", "--format", "json"}, &stdout, &stderr, dependencies)
		if code != ExitOK {
			t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitOK, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), `"schema_version":"scadenza.scan/v1"`) {
			t.Fatalf("the run reported no document: %s", stdout.String())
		}
		if strings.Contains(stderr.String(), interruptedMessage) {
			t.Fatalf("the run reported an interrupt: %s", stderr.String())
		}
	})
}

// TestRunInterruptedBeforeItStartsWritesNothing proves that a run whose
// context was already cancelled by an interrupt does nothing at all: the exit
// code is 130, stdout stays empty, and the last line on stderr is
// `interrupted`. The version command is part of the case, because it writes
// to stdout as well.
func TestRunInterruptedBeforeItStartsWritesNothing(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{name: "the version command", args: []string{"version"}},
		{name: "the ct command", args: []string{"ct", "example.com"}},
		{name: "the scan command", args: []string{"scan", "--domain", "example.com"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(context.Background())
			cancel(ErrInterrupted)
			var stdout, stderr bytes.Buffer
			code := ExecuteContext(ctx, test.args, &stdout, &stderr)
			if code != ExitInterrupted {
				t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitInterrupted, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("the interrupted run wrote to stdout: %s", stdout.String())
			}
			if last := lastLine(stderr.String()); last != interruptedMessage {
				t.Fatalf("stderr = %q, want the last line %q", stderr.String(), interruptedMessage)
			}
		})
	}
}

// TestCommandBodiesCheckAnInterruptBeforeWork proves that each command body
// independently checks for an interrupt before it does any work. The normal
// execute path has an earlier guard; constructing the command tree directly
// isolates the body guards so a missing guard cannot be hidden by that one.
// The fake sources record that they were called, so a missing body guard
// fails the test even though the later checks would still stop the run. The
// scan case requests a vault because the Azure read is the first source work
// the scan body does.
func TestCommandBodiesCheckAnInterruptBeforeWork(t *testing.T) {
	cases := []struct {
		name string
		args []string
		wire func(ct.Source) ctDependencies
	}{
		{name: "the version command", args: []string{"version"}},
		{
			name: "the ct command",
			args: []string{"ct", "example.com", "--source", "certspotter", "--format", "json"},
			wire: interruptDependencies,
		},
		{
			name: "the scan command",
			args: []string{"scan", "--domain", "example.com", "--source", "certspotter", "--azure-keyvault", "https://example.vault.azure.net", "--format", "json"},
			wire: func(source ct.Source) ctDependencies { return wiringDependencies(source, matchedProber()) },
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			source := &recordingCTSource{fakeCTSource: fakeCTSource{name: "certspotter", certificates: []ct.Certificate{ctRecord("example.com")}}}
			dependencies := ctDependencies{}
			if test.wire != nil {
				dependencies = test.wire(source)
			}
			azureCalled := false
			dependencies.loadAzure = func(azurekv.LoadOptions) (azurekv.Source, error) {
				azureCalled = true
				return azureSourceStub{}, nil
			}
			ctx, cancel := context.WithCancelCause(context.Background())
			cancel(ErrInterrupted)
			var stdout, stderr bytes.Buffer
			root := newRootCommand(&stdout, &stderr, dependencies, &runState{})
			root.SetArgs(test.args)
			err := root.ExecuteContext(ctx)
			if code := exitCode(err); code != ExitInterrupted {
				t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitInterrupted, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("the interrupted command body wrote to stdout: %s", stdout.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("the interrupted command body wrote to stderr: %s", stderr.String())
			}
			if source.called || azureCalled {
				t.Fatalf("the command body reached a source despite the interrupt")
			}
		})
	}
}

// TestInterruptedRunKeepsItsDiagnostics proves the stderr contract of an
// interrupted run: the diagnostics the run printed before the interrupt stay
// on stderr, and the interrupt is the last line.
func TestInterruptedRunKeepsItsDiagnostics(t *testing.T) {
	prober := &blockingProber{started: make(chan struct{}, 1)}
	dependencies := wiringDependencies(scanSource(false), prober)
	ctx, cancel := context.WithCancelCause(context.Background())
	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- execute(ctx, []string{"scan", "--domain", "example.com", "--source", "certspotter", "--format", "json"}, &stdout, &stderr, dependencies)
	}()
	<-prober.started
	cancel(ErrInterrupted)
	code := <-done
	if code != ExitInterrupted {
		t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitInterrupted, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("the interrupted run reported a result: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "SCD-0002") {
		t.Fatalf("the diagnostic printed before the interrupt was lost: %s", stderr.String())
	}
	if last := lastLine(stderr.String()); last != interruptedMessage {
		t.Fatalf("stderr = %q, want the last line %q", stderr.String(), interruptedMessage)
	}
}

// TestRunInterruptedAfterTheDocumentKeepsItsExitCode proves that a run whose
// document was already written is complete: a signal that arrives after the
// write does not change the exit code and does not print the interrupt line.
func TestRunInterruptedAfterTheDocumentKeepsItsExitCode(t *testing.T) {
	t.Run("a clean run exits 0", func(t *testing.T) {
		source := &fakeCTSource{name: "certspotter", certificates: []ct.Certificate{ctRecord("example.com")}}
		ctx, cancel := context.WithCancelCause(context.Background())
		defer cancel(nil)
		stdout := &cancellingWriter{cancel: cancel}
		var stderr bytes.Buffer
		code := execute(ctx, []string{"ct", "example.com", "--source", "certspotter", "--format", "json"}, stdout, &stderr, interruptDependencies(source))
		if code != ExitOK {
			t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitOK, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), `"schema_version":"scadenza.ct/v1"`) {
			t.Fatalf("the run reported no document: %s", stdout.String())
		}
		if strings.Contains(stderr.String(), interruptedMessage) {
			t.Fatalf("a finished run reported an interrupt: %s", stderr.String())
		}
	})

	t.Run("a blocking finding exits 3", func(t *testing.T) {
		dependencies := wiringDependencies(scanSource(true), liveOnlyProber())
		ctx, cancel := context.WithCancelCause(context.Background())
		defer cancel(nil)
		stdout := &cancellingWriter{cancel: cancel}
		var stderr bytes.Buffer
		code := execute(ctx, []string{"scan", "--domain", "example.com", "--source", "certspotter", "--format", "json"}, stdout, &stderr, dependencies)
		if code != ExitFindingsPresent {
			t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitFindingsPresent, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), `"kind":"live_only"`) {
			t.Fatalf("the run reported no finding: %s", stdout.String())
		}
		if strings.Contains(stderr.String(), interruptedMessage) {
			t.Fatalf("a finished run reported an interrupt: %s", stderr.String())
		}
	})
}

// TestVersionInterruptedAfterTheTextKeepsItsExitCode proves that the version
// text is the document of the version command: a signal that arrives after it
// was written keeps the exit code of a finished run.
func TestVersionInterruptedAfterTheTextKeepsItsExitCode(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	stdout := &cancellingWriter{cancel: cancel}
	var stderr bytes.Buffer
	code := execute(ctx, []string{"version"}, stdout, &stderr, ctDependencies{})
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, ExitOK, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "scadenza ") {
		t.Fatalf("the run reported no version text: %s", stdout.String())
	}
	if strings.Contains(stderr.String(), interruptedMessage) {
		t.Fatalf("a finished run reported an interrupt: %s", stderr.String())
	}
}

// cancellingWriter writes the document to its buffer and cancels the run
// context when it does, so a test can interrupt the run at the exact moment
// the document is complete.
type cancellingWriter struct {
	bytes.Buffer
	cancel context.CancelCauseFunc
}

func (writer *cancellingWriter) Write(data []byte) (int, error) {
	written, err := writer.Buffer.Write(data)
	writer.cancel(ErrInterrupted)
	return written, err
}

// lastLine returns the last line of the given text, without its line ending.
func lastLine(text string) string {
	trimmed := strings.TrimRight(text, "\n")
	if trimmed == "" {
		return ""
	}
	lines := strings.Split(trimmed, "\n")
	return lines[len(lines)-1]
}
