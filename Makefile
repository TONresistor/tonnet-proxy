.PHONY: build build-all clean deps test lint

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o bin/tonnet-proxy ./cmd/

build-all:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/tonnet-proxy-linux-amd64 ./cmd/
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/tonnet-proxy-linux-arm64 ./cmd/
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/tonnet-proxy-darwin-amd64 ./cmd/
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/tonnet-proxy-darwin-arm64 ./cmd/
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/tonnet-proxy-windows-amd64.exe ./cmd/

clean:
	rm -rf bin/

deps:
	go mod download
	go mod tidy

test:
	go test -v ./...

lint:
	golangci-lint run
