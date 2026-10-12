BINARY_EXT := $(if $(filter Windows_NT,$(OS)),.exe,)
BINARY := scadenza$(BINARY_EXT)
MODULE := github.com/HarnageaGabriel/scadenza
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf unknown)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X $(MODULE)/internal/version.Version=$(VERSION) -X $(MODULE)/internal/version.Commit=$(COMMIT) -X $(MODULE)/internal/version.Date=$(DATE)

.PHONY: build test lint vuln cover fmt docs docs-check cover-floors tidy

build:
	mkdir -p bin
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/scadenza

test:
	go test -race ./...

lint:
	golangci-lint run ./...

vuln:
	govulncheck ./...

cover:
	go test -race -covermode=atomic -coverprofile=coverage.out ./internal/...

cover-floors:
	sh scripts/cover-floors.sh

fmt:
	gofmt -w $$(find cmd internal tools -type f -name '*.go')

docs:
	go run ./tools/docsgen -out docs/diagnostics

docs-check:
	go run ./tools/docsgen -out docs/diagnostics -check

tidy:
	go mod tidy
