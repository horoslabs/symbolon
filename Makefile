# symbolon — TLS/SSL audit
#
# Usage: make help

BINARY  := symbolon
PKG     := ./cmd/symbolon
OUT     := out
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
TARGET  ?= example.com

.DEFAULT_GOAL := help
.DELETE_ON_ERROR:
.PHONY: help build install run test test-race cover vet fmt fmt-check lint tidy badssl check clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-11s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary into ./symbolon
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) $(PKG)

install: ## Install symbolon into GOPATH/bin
	go install -trimpath -ldflags '$(LDFLAGS)' $(PKG)

run: build ## Build and scan TARGET (make run TARGET=badssl.com)
	./$(BINARY) scan $(TARGET)

test: ## Run the tests
	go test ./...

test-race: ## Run the tests with the race detector
	go test -race ./...

cover: ## Run the tests and generate out/coverage.out
	@mkdir -p $(OUT)
	go test -coverprofile=$(OUT)/coverage.out ./...
	go tool cover -func=$(OUT)/coverage.out

vet: ## Analyze the code with go vet
	go vet ./...

fmt: ## Format the code with gofmt
	gofmt -w .

fmt-check: ## Check that the code is formatted
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "files not gofmt'd:"; echo "$$unformatted"; exit 1; \
	fi

lint: fmt-check vet ## Formatting + go vet

tidy: ## Tidy go.mod/go.sum
	go mod tidy

badssl: build ## Scan the badssl.com test targets
	./$(BINARY) scan expired.badssl.com wrong.host.badssl.com self-signed.badssl.com \
		untrusted-root.badssl.com rc4.badssl.com 3des.badssl.com null.badssl.com \
		dh1024.badssl.com dh512.badssl.com tls-v1-0.badssl.com:1010 tls-v1-1.badssl.com:1011

check: lint test ## Formatting, vet and tests

clean: ## Remove generated artifacts
	rm -f $(BINARY)
	rm -rf $(OUT)
