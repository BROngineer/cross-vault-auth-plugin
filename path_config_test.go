package cva

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"gotest.tools/v3/assert"
)

func TestConfig_Write(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		data           map[string]interface{}
		expectedConfig *crossVaultAuthBackendConfig
		expectErr      bool
	}{
		"common": {
			data: map[string]interface{}{
				"cluster":              "http://127.0.0.1:8200",
				"insecure_skip_verify": true,
			},
			expectedConfig: &crossVaultAuthBackendConfig{
				Cluster:            "http://127.0.0.1:8200",
				Namespace:          "root",
				InsecureSkipVerify: true,
			},
			expectErr: false,
		},
		"non-root-namespace": {
			data: map[string]interface{}{
				"cluster":   "http://127.0.0.1:8200",
				"namespace": "custom-ns",
			},
			expectedConfig: &crossVaultAuthBackendConfig{
				Cluster:            "http://127.0.0.1:8200",
				Namespace:          "custom-ns",
				InsecureSkipVerify: false,
			},
			expectErr: false,
		},
		"missing-cluster": {
			data: map[string]interface{}{
				"insecure_skip_verify": true,
			},
			expectErr: true,
		},
	}

	for name, tCase := range tests {
		t.Run(name, func(t *testing.T) {
			b, storage := getBackend(t)
			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      configPath,
				Data:      tCase.data,
				Storage:   storage,
			}
			resp, err := b.HandleRequest(context.Background(), req)

			if tCase.expectErr {
				if err == nil && !resp.IsError() {
					t.Fatalf("expected error, but no error occurred")
				}
			} else {
				if err != nil || resp.IsError() {
					t.Fatalf("unexpected error")
				}
				config, err := b.(*crossVaultAuthBackend).config(context.Background(), storage)
				if err != nil {
					t.Fatal(err)
				}
				assert.DeepEqual(t, config, tCase.expectedConfig)
			}
		})
	}
}

func TestConfig_Read(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		request  map[string]interface{}
		response map[string]interface{}
	}{
		"default": {
			request: map[string]interface{}{
				"cluster": "http://127.0.0.1:8200",
			},
			response: map[string]interface{}{
				"cluster":              "http://127.0.0.1:8200",
				"namespace":            "root",
				"ca_cert":              "",
				"insecure_skip_verify": false,
			},
		},
		"custom": {
			request: map[string]interface{}{
				"cluster":              "https://127.0.0.1",
				"ca_cert":              "DATA OMITTED",
				"namespace":            "custom",
				"insecure_skip_verify": true,
			},
			response: map[string]interface{}{
				"cluster":              "https://127.0.0.1",
				"namespace":            "custom",
				"ca_cert":              "DATA OMITTED",
				"insecure_skip_verify": true,
			},
		},
	}

	for name, tCase := range tests {
		t.Run(name, func(t *testing.T) {
			b, storage := getBackend(t)
			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      configPath,
				Data:      tCase.request,
				Storage:   storage,
			}
			resp, err := b.HandleRequest(context.Background(), req)
			if err != nil || resp.IsError() {
				t.Fatal()
			}

			req = &logical.Request{
				Operation: logical.ReadOperation,
				Path:      configPath,
				Data:      nil,
				Storage:   storage,
			}
			resp, err = b.HandleRequest(context.Background(), req)
			if err != nil || resp.IsError() {
				t.Fatal()
			}
			assert.DeepEqual(t, resp.Data, tCase.response)
		})
	}
}
