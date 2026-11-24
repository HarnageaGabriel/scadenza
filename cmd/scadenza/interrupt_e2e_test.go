//go:build unix

package main

import (
	"bytes"
	"errors"
	"net"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/HarnageaGabriel/scadenza/internal/cli"
)

// TestInterruptStopsScanBinary proves with the built binary that SIGINT stops
// a scan waiting on a server that never answers: the process exits 130,
// stdout stays empty, and the last line on stderr is `interrupted`.
//
// The listener accepts the probe connection and never answers, so the TLS
// handshake keeps waiting. The signal is sent only once the listener accepted
// a connection, so the run is surely mid-probe and not already finished.
func TestInterruptStopsScanBinary(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve the test file location")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	binary := filepath.Join(t.TempDir(), "scadenza")
	build := exec.Command("go", "build", "-o", binary, "./cmd/scadenza")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var connections []net.Conn
		defer func() {
			for _, connection := range connections {
				_ = connection.Close()
			}
		}()
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			// The connection stays open without an answer, so the probe waits.
			connections = append(connections, connection)
			select {
			case accepted <- struct{}{}:
			default:
			}
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})

	command := exec.Command(binary, "scan", "--from-ct=false", "--host", listener.Addr().String(), "--format", "json")
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = command.Process.Kill() })
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()

	select {
	case <-accepted:
	case <-time.After(10 * time.Second):
		t.Fatal("the scan never connected to the listener")
	}
	if err := command.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatalf("send SIGINT: %v", err)
	}
	var waitErr error
	select {
	case waitErr = <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("the scan did not exit within 5s of SIGINT")
	}
	var exit *exec.ExitError
	if !errors.As(waitErr, &exit) || exit.ExitCode() != cli.ExitInterrupted {
		t.Fatalf("exit = %v, want %d; stdout=%s stderr=%s", waitErr, cli.ExitInterrupted, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("the interrupted scan reported a result: %s", stdout.String())
	}
	lines := strings.Split(strings.TrimRight(stderr.String(), "\n"), "\n")
	if last := lines[len(lines)-1]; last != "interrupted" {
		t.Fatalf("stderr = %q, want the last line %q", stderr.String(), "interrupted")
	}
}
