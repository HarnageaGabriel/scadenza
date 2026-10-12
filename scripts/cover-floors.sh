#!/bin/sh
set -eu
go test -coverprofile=coverage.out ./internal/...
python3 scripts/cover-floors.py
