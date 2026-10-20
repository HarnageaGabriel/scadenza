// Command scadenza inspects public TLS certificate readiness.
package main

import (
	"os"

	"github.com/HarnageaGabriel/scadenza/internal/cli"
)

func main() {
	ctx, stop := signalContext()
	code := cli.ExecuteContext(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
