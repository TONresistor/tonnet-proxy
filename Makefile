.PHONY: build build-all build-universal clean deps test lint

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION) -s -w"

build:
	go build $(LDFLAGS) -o bin/tonnet-proxy ./cmd/

build-all:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/tonnet-proxy-linux-amd64 ./cmd/
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/tonnet-proxy-linux-arm64 ./cmd/
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/tonnet-proxy-darwin-amd64 ./cmd/
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/tonnet-proxy-darwin-arm64 ./cmd/
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/tonnet-proxy-windows-amd64.exe ./cmd/

# Build macOS universal binary (x86_64 + arm64)
build-universal: build-darwin-amd64 build-darwin-arm64
	@echo "Creating universal binary..."
	lipo -create -output bin/tonnet-proxy-darwin-universal \
		bin/tonnet-proxy-darwin-amd64 \
		bin/tonnet-proxy-darwin-arm64
	@echo "Universal binary created: bin/tonnet-proxy-darwin-universal"
	@file bin/tonnet-proxy-darwin-universal

build-darwin-amd64:
	@mkdir -p bin
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/tonnet-proxy-darwin-amd64 ./cmd/

build-darwin-arm64:
	@mkdir -p bin
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/tonnet-proxy-darwin-arm64 ./cmd/

# Build all platforms with universal macOS binary
build-release: build-universal
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/tonnet-proxy-linux-amd64 ./cmd/
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/tonnet-proxy-windows-amd64.exe ./cmd/
	@echo "Release binaries built successfully"
	@ls -la bin/

clean:
	rm -rf bin/

deps:
	go mod download
	go mod tidy

test:
	go test -v ./...

lint:
	golangci-lint run
