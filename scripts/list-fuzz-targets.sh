#!/bin/sh
# Print one "<package> <FuzzTarget>" line per fuzz target.
# go test -fuzz accepts a single package, so the workflow runs each target alone.
set -eu
go list -f '{{.ImportPath}}' ./... | while read -r pkg; do
  go test -list '^Fuzz' "$pkg" 2>/dev/null | awk -v pkg="$pkg" '/^Fuzz/ {print pkg " " $1}'
done
