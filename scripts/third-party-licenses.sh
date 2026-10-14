#!/bin/sh
# Regenerate THIRD_PARTY_LICENSES/dependencies.csv: module path, license URL, license type
# for every package linked into the scadenza binary. Run after changing dependencies.
set -eu
go run github.com/google/go-licenses@v1.6.0 report ./cmd/scadenza 2>/dev/null \
  | grep -v '^github.com/HarnageaGabriel/scadenza' | LC_ALL=C sort > THIRD_PARTY_LICENSES/dependencies.csv
