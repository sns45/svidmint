VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS  = -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build test lint install clean

build:
	go build -ldflags "$(LDFLAGS)" -o bin/svidmint ./cmd/svidmint

test:
	go test -race ./...

lint:
	golangci-lint run ./...

install:
	go install -ldflags "$(LDFLAGS)" ./cmd/svidmint

clean:
	rm -rf bin/
