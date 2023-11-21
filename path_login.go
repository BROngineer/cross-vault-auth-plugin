package cva

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	loginHelpSynopsis    = "Login with the provided role"
	loginHelpDescription = `
During Cross Vault authentication process, backend will validate provided token 
at the peered Vault cluster and issue new token in case validation will be passed.
`

	tokenLookupPath = "auth/token/lookup"
)

func (b *crossVaultAuthBackend) pathLogin() *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: "Name of the role to login. The field is mandatory.",
			},
			"token": {
				Type:        framework.TypeString,
				Description: "Token issued by the peered Vault cluster. The field is mandatory.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.login,
			},
		},
		HelpSynopsis:    loginHelpSynopsis,
		HelpDescription: loginHelpDescription,
	}
}

func (b *crossVaultAuthBackend) login(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	roleName := data.Get("role").(string)
	if roleName == "" {
		return logical.ErrorResponse("'role' field is mandatory"), nil
	}
	token := data.Get("token").(string)
	if token == "" {
		return logical.ErrorResponse("'token' field is mandatory"), nil
	}

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role with provided name not found"), nil
	}

	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// here I assume that there is VAULT_TOKEN env variable is already set.
	// this assumption comes from the very concrete use case - when current
	// vault cluster uses transit unseal option, so it is already authenticated
	// in the target vault cluster.
	// todo: extend backend with configuration options providing authentication
	//   config which will be used to authenticate in target cluster
	vc, err := api.NewClient(b.newConfig(config))
	if err != nil {
		return nil, err
	}

	requestCtx, cancel := context.WithTimeout(ctx, tokenLookupTimeout)
	defer cancel()
	resp, err := vc.Logical().WriteWithContext(requestCtx, tokenLookupPath, map[string]interface{}{"token": token})
	if err != nil {
		return nil, err
	}
	validated, err := b.validateResponse(resp, role)
	if err != nil {
		return nil, err
	}
	if !validated {
		return logical.ErrorResponse("role validation failed"), nil
	}

	auth := &logical.Auth{
		InternalData: map[string]interface{}{"role": roleName},
		DisplayName:  fmt.Sprintf("%s-%s", roleName, role.EntityID),
		Metadata:     map[string]string{"role": roleName, "mapped_entity_id": role.EntityID},
	}
	role.PopulateTokenAuth(auth)

	return &logical.Response{Auth: auth}, nil
}

func (b *crossVaultAuthBackend) newConfig(config *crossVaultAuthBackendConfig) *api.Config {
	vaultClientConfig := api.DefaultConfig()
	vaultClientConfig.HttpClient = b.httpClient
	vaultClientConfig.Address = config.Cluster
	return vaultClientConfig
}

func (b *crossVaultAuthBackend) validateResponse(body *api.Secret, role *crossVaultAuthRoleEntry) (bool, error) {
	entityID := body.Data["entity_id"]
	if entityID != role.EntityID {
		return false, nil
	}

	raw, err := json.Marshal(body.Data["meta"])
	if err != nil {
		return false, err
	}
	metadata := make(map[string]string)
	err = json.Unmarshal(raw, &metadata)
	if err != nil {
		return false, err
	}

	if role.StrictMetaVerify {
		if !reflect.DeepEqual(metadata, role.EntityMeta) {
			return false, nil
		}
	}
	for key, value := range role.EntityMeta {
		v := metadata[key]
		if value != v {
			return false, nil
		}
	}

	return true, nil
}
