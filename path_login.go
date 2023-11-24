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
During Cross Vault authentication process, backend will validate provided token or token
accessor at the peered Vault cluster and issue new token in case validation will be passed.
`

	tokenLookupPath    = "auth/token/lookup"
	tokenPayloadKey    = "token"
	accessorLookupPath = "auth/token/lookup-accessor"
	accessorPayloadKey = "accessor"
)

func (b *crossVaultAuthBackend) pathLogin() *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: "Name of the role to login. The field is mandatory.",
			},
			"secret": {
				Type: framework.TypeString,
				Description: "Token issued by the peered Vault cluster or token accessor if " +
					"corresponding flag set to true. The field is mandatory.",
			},
			"accessor": {
				Type: framework.TypeBool,
				Description: "Flag defines whether provided token is the token accessor " +
					"or token itself. Default value is 'false'",
			},
			// todo: instead of field "accessor" add field "method" with possible values:
			//	 - wrapped-token-full: "secret" field should contains wrapping toking with full token data obtained by '-wrap-ttl=N write auth/.../login'
			//	 - wrapped-token-only: "secret" field should contain wrapping token with target token itself wrapped using cubbyhole secret engine
			//	 - wrapped-accessor-only: "secret" field should contain wrapping token with target token accessor wrapped using cubbyhole secret engine
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.login,
			},
			logical.AliasLookaheadOperation: &framework.PathOperation{
				Callback: b.loginAliasLookahead,
			},
		},
		HelpSynopsis:    loginHelpSynopsis,
		HelpDescription: loginHelpDescription,
	}
}

func (b *crossVaultAuthBackend) loginAliasLookahead(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	roleName, _ := data.Get("role").(string)
	if roleName == "" {
		return nil, fmt.Errorf("'role' field is mandatory")
	}

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Auth: &logical.Auth{
			Alias: &logical.Alias{
				Name: role.RoleID,
			},
		},
	}, nil
}

func (b *crossVaultAuthBackend) login(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	var (
		resp *api.Secret
		err  error
	)

	lookupPath := tokenLookupPath
	lookupPayloadKey := tokenPayloadKey

	roleName, _ := data.Get("role").(string)
	if roleName == "" {
		return logical.ErrorResponse("'role' field is mandatory"), nil
	}
	secret, _ := data.Get("secret").(string)
	if secret == "" {
		return logical.ErrorResponse("'secret' field is mandatory"), nil
	}
	isAccessor, _ := data.Get("accessor").(bool)

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
	// in the target vault cluster via vault agent.
	// todo: extend backend with configuration options providing authentication
	//   config which will be used to authenticate in target cluster
	vc, err := api.NewClient(b.newConfig(config))
	if err != nil {
		return nil, err
	}

	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	if isAccessor {
		lookupPath = accessorLookupPath
		lookupPayloadKey = accessorPayloadKey
	}
	resp, err = vc.Logical().WriteWithContext(requestCtx, lookupPath, map[string]interface{}{lookupPayloadKey: secret})
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

	metadata := map[string]string{"role": roleName, "mapped_entity_id": role.EntityID}

	auth := &logical.Auth{
		InternalData: map[string]interface{}{"role": roleName},
		DisplayName:  fmt.Sprintf("%s-%s", roleName, role.EntityID),
		Metadata:     metadata,
		Alias: &logical.Alias{
			Name:     role.RoleID,
			Metadata: metadata,
		},
	}
	role.PopulateTokenAuth(auth)
	auth.Renewable = false

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
