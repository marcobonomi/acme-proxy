VERSION ?= dev
GOARCH  ?= amd64
BIN     := bin/acme-proxy
PKG     := ./cmd/acme-proxy

.PHONY: build test lint clean

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build -trimpath \
		-ldflags "-s -w -X main.version=$(VERSION)" -o $(BIN) $(PKG)

test:
	go test -race ./...

lint:
	go vet ./...
	staticcheck ./...

clean:
	rm -rf bin
