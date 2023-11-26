package cva

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
)

const (
	minTLSVersion = tls.VersionTLS12

	loginPath  = "login"
	configPath = "config"
	rolePath   = "role"

	tlsUpdateTicker = time.Second * 30
	requestTimeout  = time.Second * 30
)

var (
	backendHelp = "The Cross-Vault Auth Backend allows authentication through another Vault cluster"

	httpClientIsNotSet            = errors.New("HTTP client is not set")
	tlsConfigIsNotSet             = errors.New("TLS config is not set")
	typeAssertionFailed           = errors.New("type assertion failed")
	unknownLoginMethod            = errors.New("unknown login method")
	tokenNotFoundInWrappedData    = errors.New("token not found in wrapped data, expect data stored in key 'secret'")
	accessorNotFoundInWrappedData = errors.New("accessor not found in wrapped data, expect data stored in key 'secret'")
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

	// ctx is the context used for requests to upstream Vault cluster
	ctx context.Context
	// cancel function for ctx
	cancel context.CancelFunc

	// vc is the vault client instance
	vc *api.Client
}

func defaultHTTPClient() *http.Client {
	return cleanhttp.DefaultPooledClient()
}

func defaultTLSConfig() *tls.Config {
	return &tls.Config{MinVersion: minTLSVersion}
}

func validateHTTPClient(b *crossVaultAuthBackend) error {
	if b.httpClient == nil {
		return httpClientIsNotSet
	}
	if b.tlsConfig == nil {
		return tlsConfigIsNotSet
	}
	return nil
}

// Factory returns new instance of crossVaultAuthBackend as logical.Backend.
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
		Help: backendHelp,
		Paths: framework.PathAppend(
			[]*framework.Path{
				b.pathConfig(),
				b.pathRole(),
				b.pathRoleList(),
				b.pathLogin(),
			},
		),
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				loginPath,
			},
			SealWrapStorage: []string{
				configPath,
			},
		},
		InitializeFunc: b.initialize,
		Clean:          b.cleanup,
		BackendType:    logical.TypeCredential,
	}

	return b
}

func (b *crossVaultAuthBackend) initialize(ctx context.Context, req *logical.InitializationRequest) error {
	tlsUpdaterContext, tlsUpdaterCancel := context.WithCancel(ctx)
	if err := b.runTLSConfigUpdater(tlsUpdaterContext, req.Storage, tlsUpdateTicker); err != nil {
		tlsUpdaterCancel()
		return err
	}
	b.tlsConfigUpdateCancel = tlsUpdaterCancel
	return nil
}

func (b *crossVaultAuthBackend) cleanup(_ context.Context) {
	if b.tlsConfigUpdateCancel != nil {
		b.tlsConfigUpdateCancel()
		b.tlsConfigUpdateCancel = nil
	}
}

func (b *crossVaultAuthBackend) config(ctx context.Context, storage logical.Storage) (*crossVaultAuthBackendConfig, error) {
	var (
		raw *logical.StorageEntry
		err error
	)

	raw, err = storage.Get(ctx, configPath)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	config := &crossVaultAuthBackendConfig{}
	if err = json.Unmarshal(raw.Value, config); err != nil {
		return nil, err
	}

	return config, nil
}

func (b *crossVaultAuthBackend) runTLSConfigUpdater(
	ctx context.Context,
	storage logical.Storage,
	period time.Duration,
) error {
	var (
		wg  sync.WaitGroup
		err error
	)

	b.tlsMu.Lock()
	defer b.tlsMu.Unlock()

	if b.tlsConfigUpdateRunning {
		return nil
	}

	if err = validateHTTPClient(b); err != nil {
		return err
	}

	wg.Add(1)
	ticker := time.NewTicker(period)
	go func(ctx context.Context, storage logical.Storage) {
		defer func() {
			b.tlsMu.Lock()
			ticker.Stop()
			b.tlsConfigUpdateRunning = false
			b.Logger().Trace("TLS config updater shutdown complete")
			b.tlsMu.Unlock()
		}()

		b.tlsConfigUpdateRunning = true
		wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err = updateTLSConfig(ctx, b, storage); err != nil {
					b.Logger().Warn("TLS config update failed", "error", err)
				}
			}
		}
	}(ctx, storage)
	wg.Wait()
	return nil
}

func (b *crossVaultAuthBackend) updateTLSConfig(config *crossVaultAuthBackendConfig) error {
	var caCertBytes []byte

	b.tlsMu.Lock()
	defer b.tlsMu.Unlock()

	if err := validateHTTPClient(b); err != nil {
		return err
	}

	if config.CACert != "" {
		caCertBytes = []byte(config.CACert)
	}

	certPool := x509.NewCertPool()
	if len(caCertBytes) > 0 {
		if ok := certPool.AppendCertsFromPEM(caCertBytes); !ok {
			b.Logger().Warn("Provided CA certificate data does not contain valid certificates")
		}
	} else {
		b.Logger().Warn("No CA certificates provided")
	}

	if !b.tlsConfig.RootCAs.Equal(certPool) {
		transport, ok := b.httpClient.Transport.(*http.Transport)
		if !ok {
			return typeAssertionFailed
		}
		b.tlsConfig.RootCAs = certPool
		b.tlsConfig.InsecureSkipVerify = config.InsecureSkipVerify
		transport.TLSClientConfig = b.tlsConfig
	}

	return nil
}

func updateTLSConfig(ctx context.Context, b *crossVaultAuthBackend, storage logical.Storage) error {
	config, err := b.config(ctx, storage)
	if err != nil {
		return err
	}

	if config == nil {
		b.Logger().Trace("configuration is not set, TLS config update skipped")
		return nil
	}

	if err = b.updateTLSConfig(config); err != nil {
		return err
	}
	return nil
}

func (b *crossVaultAuthBackend) role(
	ctx context.Context,
	storage logical.Storage,
	name string,
) (*crossVaultAuthRoleEntry, error) {
	var (
		raw *logical.StorageEntry
		err error
	)

	raw, err = storage.Get(ctx, fmt.Sprintf("%s/%s", rolePath, strings.ToLower(name)))
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	role := &crossVaultAuthRoleEntry{}
	if err = json.Unmarshal(raw.Value, role); err != nil {
		return nil, err
	}

	return role, nil
}
