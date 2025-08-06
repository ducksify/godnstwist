.PHONY: all build test clean install

all: build

build:
	@echo "Building dnstwist..."
	@go build -o bin/dnstwist cmd/dnstwist/main.go

test:
	@echo "Running tests..."
	@go test -v ./...

clean:
	@echo "Cleaning..."
	@rm -rf bin/

install: build
	@echo "Installing dnstwist..."
	@cp bin/dnstwist /usr/local/bin/

deps:
	@echo "Downloading dependencies..."
	@go mod download

lint:
	@echo "Running linter..."
	@go vet ./...

fmt:
	@echo "Formatting code..."
	@go fmt ./...

uninstall:
	rm -f /usr/local/bin/dnstwist 