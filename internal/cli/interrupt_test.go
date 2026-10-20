package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

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

// TestCTInterruptedStopsTheRun proves that an interrupt stops the run at
// once: the exit code is 130, nothing is written to stdout, and stderr
// carries exactly one line.
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
	if stderr.String() != interruptedMessage+"\n" {
		t.Fatalf("stderr = %q, want the single line %q", stderr.String(), interruptedMessage)
	}
}

// TestScanInterruptedStopsTheRun proves that an interrupt during a handshake
// stops the scan the same way: exit 130, no document on stdout, and one line
// on stderr.
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
	if stderr.String() != interruptedMessage+"\n" {
		t.Fatalf("stderr = %q, want the single line %q", stderr.String(), interruptedMessage)
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
