BINARY   := octra
MODULE   := github.com/protobuffalo/go-octra
GOFLAGS  :=

.PHONY: all build clean vet test

all: build

build:
	CGO_ENABLED=1 go build $(GOFLAGS) -o $(BINARY) .

vet:
	CGO_ENABLED=1 go vet ./...

test:
	CGO_ENABLED=1 go test ./...

clean:
	rm -f $(BINARY)
