OS=$(shell go env GOOS)
ARCH=$(shell go env GOARCH)

.PHONY: build
build:
	GOOS=${OS} GOARCH="${ARCH}" go build -o vault/plugins/cva-plugin cmd/cross-vault-auth-plugin/main.go

.PHONY: build-linux
build-linux:
	GOOS=linux GOARCH="arm64" go build -o vault/plugins/cva-plugin cmd/cross-vault-auth-plugin/main.go

.PHONY: clean
clean:
	rm -f ./vault/plugins/cva-plugin

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: test
test:
	go test -cover ./...

.PHONY: lint
lint: vet fmt golangci-lint
	$(GOLANGCI_LINT) run ./...

LOCAL_BIN ?= $(shell pwd)/bin
$(LOCAL_BIN):
	mkdir -p $(LOCAL_BIN)

GOLANGCI_LINT ?= $(LOCAL_BIN)/golangci-lint
GOLANGCI_LINT_VERSION ?= v1.56.2

.PHONY: golangci-lint
golangci-lint:
	test -s $(GOLANGCI_LINT) && $(GOLANGCI_LINT) --version | grep -q $(GOLANGCI_LINT_VERSION) || \
	GOBIN=$(LOCAL_BIN) go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)