package cva

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
	"gotest.tools/v3/assert"
)

func TestRole_Write(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		data         map[string]interface{}
		expectedRole *crossVaultAuthRoleEntry
		expectErr    bool
	}{
		"default": {
			data: map[string]interface{}{
				"entity_id": "11112222-3333-4444-5555-666677778888",
			},
			expectedRole: &crossVaultAuthRoleEntry{
				TokenParams: tokenutil.TokenParams{
					TokenType: logical.TokenTypeDefault,
				},
				EntityID: "11112222-3333-4444-5555-666677778888",
			},
		},
		"with-token-params": {
			data: map[string]interface{}{
				"entity_id":      "11112222-3333-4444-5555-666677778888",
				"token_ttl":      "10m",
				"token_policies": "test,sample",
			},
			expectedRole: &crossVaultAuthRoleEntry{
				TokenParams: tokenutil.TokenParams{
					TokenType:     logical.TokenTypeDefault,
					TokenTTL:      time.Minute * 10,
					TokenPolicies: []string{"test", "sample"},
				},
				EntityID: "11112222-3333-4444-5555-666677778888",
			},
		},
		"with-error": {
			data: map[string]interface{}{
				"token_ttl":      "10m",
				"token_policies": "test,sample",
			},
			expectErr: true,
		},
	}

	for n, tc := range tests {
		name, tCase := n, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b, storage := getBackend(t)
			req := &logical.Request{
				Operation: logical.CreateOperation,
				Path:      fmt.Sprintf("%s/%s", rolePath, name),
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
				role, err := b.(*crossVaultAuthBackend).role(context.Background(), storage, name)
				if err != nil {
					t.Fatal(err)
				}
				// zeroing role id since it has generated value and assertion is not possible
				role.RoleID = ""
				assert.DeepEqual(t, role, tCase.expectedRole)
			}
		})
	}
}

func TestRole_Read(t *testing.T) {
	t.Parallel()

	var emptyMeta map[string]string

	tests := map[string]struct {
		request  map[string]interface{}
		response map[string]interface{}
	}{
		"default": {
			request: map[string]interface{}{
				"entity_id": "11112222-3333-4444-5555-666677778888",
			},
			response: map[string]interface{}{
				"entity_id":               "11112222-3333-4444-5555-666677778888",
				"entity_meta":             emptyMeta,
				"strict_meta_verify":      false,
				"token_bound_cidrs":       []string{},
				"token_explicit_max_ttl":  int64(0),
				"token_max_ttl":           int64(0),
				"token_no_default_policy": false,
				"token_num_uses":          0,
				"token_period":            int64(0),
				"token_policies":          []string{},
				"token_ttl":               int64(0),
				"token_type":              "default",
			},
		},
		"with-token-params": {
			request: map[string]interface{}{
				"entity_id":      "11112222-3333-4444-5555-666677778888",
				"token_ttl":      "10m",
				"token_policies": "test,sample",
			},
			response: map[string]interface{}{
				"entity_id":               "11112222-3333-4444-5555-666677778888",
				"entity_meta":             emptyMeta,
				"strict_meta_verify":      false,
				"token_bound_cidrs":       []string{},
				"token_explicit_max_ttl":  int64(0),
				"token_max_ttl":           int64(0),
				"token_no_default_policy": false,
				"token_num_uses":          0,
				"token_period":            int64(0),
				"token_policies":          []string{"test", "sample"},
				"token_ttl":               int64(600),
				"token_type":              "default",
			},
		},
		"with-metadata": {
			request: map[string]interface{}{
				"entity_id":          "11112222-3333-4444-5555-666677778888",
				"entity_meta":        "env=prod",
				"strict_meta_verify": true,
			},
			response: map[string]interface{}{
				"entity_id":               "11112222-3333-4444-5555-666677778888",
				"entity_meta":             map[string]string{"env": "prod"},
				"strict_meta_verify":      true,
				"token_bound_cidrs":       []string{},
				"token_explicit_max_ttl":  int64(0),
				"token_max_ttl":           int64(0),
				"token_no_default_policy": false,
				"token_num_uses":          0,
				"token_period":            int64(0),
				"token_policies":          []string{},
				"token_ttl":               int64(0),
				"token_type":              "default",
			},
		},
	}

	for n, tc := range tests {
		name, tCase := n, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b, storage := getBackend(t)
			req := &logical.Request{
				Operation: logical.CreateOperation,
				Path:      fmt.Sprintf("%s/%s", rolePath, name),
				Data:      tCase.request,
				Storage:   storage,
			}
			resp, err := b.HandleRequest(context.Background(), req)
			if err != nil || resp.IsError() {
				t.Fatal()
			}

			req = &logical.Request{
				Operation: logical.ReadOperation,
				Path:      fmt.Sprintf("%s/%s", rolePath, name),
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

func TestRole_Delete(t *testing.T) {
	t.Parallel()

	data := map[string]interface{}{
		"entity_id": "11112222-3333-4444-5555-666677778888",
	}

	b, storage := getBackend(t)
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("%s/%s", rolePath, "default"),
		Data:      data,
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || resp.IsError() {
		t.Fatal()
	}

	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      fmt.Sprintf("%s/%s", rolePath, "default"),
		Data:      nil,
		Storage:   storage,
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || resp.IsError() {
		t.Fatal()
	}

	role, err := b.(*crossVaultAuthBackend).role(context.Background(), storage, "default")
	if err != nil {
		t.Fatal(err)
	}
	if role != nil {
		t.Fatal()
	}
}
