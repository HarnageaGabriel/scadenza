package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMaxDurationStopsSlowScan proves with the built binary that the maximum
// duration stops a scan whose only probe never answers: the document is still
// written, the probe source is failed or partial, and SCD-0035 is reported
// once. The exit code follows docs/exit-codes.md: 0 without --strict, because
// a failed probe is a probe_errors entry and no external source was requested,
// and 5 with --strict. No signals are involved, so the test runs on every OS.
func TestMaxDurationStopsSlowScan(t *testing.T) {
	binary := buildScadenza(t)
	address := silentListener(t)

	stdout, stderr, code := runLimitedScan(t, binary, address)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stdout=%s stderr=%s", code, stdout, stderr)
	}
	var document struct {
		SchemaVersion string `json:"schema_version"`
		Coverage      struct {
			Sources []struct {
				Name   string `json:"name"`
				Status string `json:"status"`
			} `json:"sources"`
		} `json:"coverage"`
	}
	if err := json.Unmarshal(stdout, &document); err != nil {
		t.Fatalf("decode scan JSON: %v\n%s", err, stdout)
	}
	if document.SchemaVersion != "scadenza.scan/v1" {
		t.Fatalf("schema_version = %q, want the scan document; stdout=%s", document.SchemaVersion, stdout)
	}
	probeStatus := ""
	for _, source := range document.Coverage.Sources {
		if source.Name == "tls" {
			probeStatus = source.Status
		}
	}
	if probeStatus != "failed" && probeStatus != "partial" {
		t.Fatalf("tls coverage = %q, want failed or partial; stdout=%s", probeStatus, stdout)
	}
	if got := strings.Count(string(stderr), "SCD-0035"); got != 1 {
		t.Fatalf("stderr reported SCD-0035 %d times, want once: %s", got, stderr)
	}

	_, stderr, code = runLimitedScan(t, binary, address, "--strict")
	if code != 5 {
		t.Fatalf("exit with --strict = %d, want 5; stderr=%s", code, stderr)
	}
}

// buildScadenza builds the real CLI into a temporary directory so the test
// exercises the shipped binary rather than the in-process command.
func buildScadenza(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve the test file location")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	name := "scadenza"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary := filepath.Join(t.TempDir(), name)
	build := exec.Command("go", "build", "-o", binary, "./cmd/scadenza")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	return binary
}

// silentListener accepts connections and never answers, so the TLS probe
// waits until the maximum duration stops it. The listener and every accepted
// connection are closed on cleanup, even when the test fails.
func silentListener(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// With nothing referencing an accepted connection the GC can finalize it
	// and close the socket, turning the probe's wait into an early EOF.
	// Keeping the connections alive makes the probe wait for the deadline.
	var held sync.Mutex
	var heldConnections []net.Conn
	t.Cleanup(func() {
		_ = listener.Close()
		held.Lock()
		defer held.Unlock()
		for _, connection := range heldConnections {
			_ = connection.Close()
		}
		heldConnections = nil
	})
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			held.Lock()
			heldConnections = append(heldConnections, connection)
			held.Unlock()
		}
	}()
	return listener.Addr().String()
}

// runLimitedScan runs the binary against the silent listener with a 300ms
// limit. The typed host is never address-guarded, so the loopback listener is
// probed. The context timeout kills the process if the limit fails to stop
// it, so a hang fails the test instead of hanging it.
func runLimitedScan(t *testing.T, binary, address string, extraArgs ...string) ([]byte, []byte, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	args := []string{"scan", "--host", address, "--max-duration", "300ms", "--format", "json"}
	args = append(args, extraArgs...)
	command := exec.CommandContext(ctx, binary, args...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if err == nil {
		return stdout.Bytes(), stderr.Bytes(), 0
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("scan: %v\nstderr:\n%s", err, stderr.Bytes())
	}
	if ctx.Err() != nil {
		t.Fatalf("the run did not stop within the timeout: %v\nstderr:\n%s", err, stderr.Bytes())
	}
	return stdout.Bytes(), stderr.Bytes(), exit.ExitCode()
}
