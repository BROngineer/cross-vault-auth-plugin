package cva

import (
	"context"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
)

func getBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()
	defaultLeaseTTL := time.Hour * 24
	maxLeaseTTL := time.Hour * 24

	b := backend()
	if err := validateHTTPClient(b); err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	config := &logical.BackendConfig{
		Logger: logging.NewVaultLogger(log.Trace),
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTL,
			MaxLeaseTTLVal:     maxLeaseTTL,
		},
		StorageView: &logical.InmemStorage{},
	}
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatalf("failed to setup backend: %v", err)
	}

	return b, config.StorageView
}
