.PHONY: build build-all lint test vet clean all

BINARY=tonnet-proxy
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

build:
	go build -ldflags "-X main.version=$(VERSION) -s -w" -o $(BINARY) ./cmd/main.go

build-all:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-X main.version=$(VERSION) -s -w" -o $(BINARY)-linux-amd64 ./cmd/main.go
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-X main.version=$(VERSION) -s -w" -o $(BINARY)-linux-arm64 ./cmd/main.go
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-X main.version=$(VERSION) -s -w" -o $(BINARY)-darwin-amd64 ./cmd/main.go
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-X main.version=$(VERSION) -s -w" -o $(BINARY)-darwin-arm64 ./cmd/main.go
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-X main.version=$(VERSION) -s -w" -o $(BINARY)-windows-amd64.exe ./cmd/main.go

lint:
	golangci-lint run ./...

test:
	go test -v -race ./...

vet:
	go vet ./...

clean:
	rm -f $(BINARY)

all: lint vet build
