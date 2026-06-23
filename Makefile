BINARY  := wisec-agent
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build static test fmt clean

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

# static produces the stripped, statically linked binary published for releases.
static:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

test:
	go test ./...

fmt:
	gofmt -w .
	go vet ./...

clean:
	rm -f $(BINARY)
