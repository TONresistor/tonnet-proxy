.PHONY: build lint test vet clean all

BINARY=adnl-proxy
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

build:
	go build -ldflags "-X main.version=$(VERSION) -s -w" -o $(BINARY) ./cmd/main.go

lint:
	golangci-lint run ./...

test:
	go test -v -race ./...

vet:
	go vet ./...

clean:
	rm -f $(BINARY)

all: lint vet build
