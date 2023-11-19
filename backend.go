package cva

import (
	"context"
	"crypto/tls"
	"net/http"
	"sync"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	minTLSVersion = tls.VersionTLS12
)

var (
	backendHelp = "The Cross-Vault Auth Backend allows authentication through another Vault cluster"
)

type crossVaultAuthBackend struct {
	*framework.Backend

	// HTTP client to be used in vault.Client instance to interact with upstream Vault cluster
	httpClient *http.Client

	// tlsConfig for vault.Client. Periodically updated to handle CA certificate changes
	tlsConfig *tls.Config

	// tlsConfigUpdateRunning reflects the current state of the tlsConfig update process
	tlsConfigUpdateRunning bool

	// tlsConfigUpdateCancel should be called on backend's shutdown
	tlsConfigUpdateCancel context.CancelFunc

	// default mutex provides thread safety for regular operations
	mu sync.RWMutex

	// tlsMu provides thread safety for TLS configuration updates operations
	tlsMu sync.RWMutex
}

func defaultHTTPClient() *http.Client {
	return cleanhttp.DefaultPooledClient()
}

func defaultTLSConfig() *tls.Config {
	return &tls.Config{MinVersion: minTLSVersion}
}

// Factory returns new instance of crossVaultAuthBackend as logical.Backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func backend() *crossVaultAuthBackend {
	b := &crossVaultAuthBackend{
		httpClient: defaultHTTPClient(),
		tlsConfig:  defaultTLSConfig(),
	}

	b.Backend = &framework.Backend{
		Help:           backendHelp,
		Paths:          framework.PathAppend(),
		PathsSpecial:   &logical.Paths{},
		InitializeFunc: b.initialize,
		Clean:          b.cleanup,
		BackendType:    logical.TypeCredential,
	}

	return b
}

func (b *crossVaultAuthBackend) initialize(ctx context.Context, req *logical.InitializationRequest) error {
	_, tlsUpdaterCancel := context.WithCancel(ctx)
	b.tlsConfigUpdateCancel = tlsUpdaterCancel

	return nil
}

func (b *crossVaultAuthBackend) cleanup(_ context.Context) {
	if b.tlsConfigUpdateCancel != nil {
		b.tlsConfigUpdateCancel()
		b.tlsConfigUpdateCancel = nil
	}
}
