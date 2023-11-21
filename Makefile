OS=$(shell go env GOOS)
ARCH=$(shell go env GOARCH)

all: fmt build start

build:
	GOOS=${OS} GOARCH="${ARCH}" go build -o vault/plugins/cva-plugin cmd/cross-vault-auth-plugin/main.go

start:
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins

enable:
	vault auth enable -path=cva-auth cva-plugin

clean:
	rm -f ./vault/plugins/cva-plugin

fmt:
	go fmt $$(go list ./...)

lint:
	golangci-lint run ./...

.PHONY: build clean fmt start enable