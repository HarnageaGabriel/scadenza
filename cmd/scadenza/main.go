// Command scadenza inspects public TLS certificate readiness.
package main

import (
	"os"

	"github.com/HarnageaGabriel/scadenza/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr))
}
