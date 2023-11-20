package cva

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
)

const (
	roleListHelpSynopsis    = "List registered roles."
	roleListHelpDescription = "The list contains roles' names."

	roleHelpSynopsis    = "Register the role"
	roleHelpDescription = `
A registered role is required to authenticate with this backend. 
The role's configuration provides data which is used to ensure that 
token provided for authentication and issued by the another Vault 
cluster is valid for authentication.`
)

var (
	roleStorageEntryCreateFailed = errors.New("failed to create storage entry for role")
)

type crossVaultAuthRoleEntry struct {
	tokenutil.TokenParams

	// EntityID stores uuid of the entity, token being validated was issued for
	EntityID string `json:"entity_id" mapstructure:"entity_id" structs:"entity_id"`

	// EntityMeta stores metadata applied to the entity in the target Vault cluster
	EntityMeta map[string]string `json:"entity_meta" mapstructure:"entity_meta" structs:"entity_meta"`

	// StrictMetaVerify defines whether metadata provided for role must be exactly
	// the same as metadata applied to the entity in the target Vault cluster
	StrictMetaVerify bool `json:"strict_meta_verify" mapstructure:"strict_meta_verify" structs:"strict_meta_verify"`
}

func (b *crossVaultAuthBackend) pathRoleList() *framework.Path {
	return &framework.Path{
		Pattern: "role/?",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.roleList,
				DisplayAttrs: &framework.DisplayAttributes{
					Navigation:    true,
					OperationVerb: "list",
					ItemType:      "Role",
				},
				Description: "returns list of registered roles",
			},
		},
		HelpSynopsis:    roleListHelpSynopsis,
		HelpDescription: roleListHelpDescription,
	}
}

func (b *crossVaultAuthBackend) roleList(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	roles, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(roles), nil
}

func (b *crossVaultAuthBackend) pathRole() *framework.Path {
	return &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The name of the role",
			},
			"entity_id": {
				Type:        framework.TypeString,
				Description: "Entity ID binding",
			},
			"entity_meta": {
				Type:        framework.TypeKVPairs,
				Description: "Entity metadata binding",
			},
			"strict_meta_verify": {
				Type:    framework.TypeBool,
				Default: false,
				Description: `Flag defines whether provided entity metadata must strictly match with 
metadata stored for target entity in target Vault cluster`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.roleWrite,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "create",
					Navigation:    true,
					ItemType:      "Role",
				},
				Description: "create role entry",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.roleWrite,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "update",
					Navigation:    true,
					ItemType:      "Role",
				},
				Description: "update role entry",
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.roleRead,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "read",
					Navigation:    true,
					ItemType:      "Role",
				},
				Description: "read registered role data",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.roleDelete,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "delete",
					Navigation:    true,
					ItemType:      "Role",
				},
				Description: "delete registered role",
			},
		},
		ExistenceCheck:  b.roleExistenceCheck,
		HelpSynopsis:    roleHelpSynopsis,
		HelpDescription: roleHelpDescription,
	}
}

func (b *crossVaultAuthBackend) roleExistenceCheck(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	role, err := b.role(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *crossVaultAuthBackend) roleWrite(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("role name must be specified"), nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	var resp *logical.Response

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	switch {
	case req.Operation == logical.CreateOperation, role == nil:
		role = &crossVaultAuthRoleEntry{}
		fallthrough
	case req.Operation == logical.UpdateOperation, role != nil:
		roleUpdCtx := context.WithValue(ctx, "roleName", roleName)
		resp, err = b.roleEntryUpdate(roleUpdCtx, req, data, role)
	default:
		if role == nil {
			resp = logical.ErrorResponse("no role with specified name found for update")
		} else {
			resp = logical.ErrorResponse("role with specified name already exists")
		}
		return resp, nil
	}

	return resp, err
}

func (b *crossVaultAuthBackend) roleRead(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("role name must be specified"), nil
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	roleData := map[string]interface{}{
		"entity_id":          role.EntityID,
		"entity_meta":        role.EntityMeta,
		"strict_meta_verify": role.StrictMetaVerify,
	}

	role.PopulateTokenData(roleData)

	return &logical.Response{
		Data: roleData,
	}, nil
}

func (b *crossVaultAuthBackend) roleDelete(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("role name must be specified"), nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if err := req.Storage.Delete(ctx, fmt.Sprintf("%s/%s", rolePath, strings.ToLower(roleName))); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *crossVaultAuthBackend) roleEntryUpdate(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
	role *crossVaultAuthRoleEntry,
) (*logical.Response, error) {
	var (
		entry *logical.StorageEntry
		resp  *logical.Response
		err   error
	)
	roleName := ctx.Value("roleName").(string)

	if err = role.ParseTokenFields(req, data); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	if role.TokenMaxTTL > time.Duration(0) && role.TokenTTL > role.TokenMaxTTL {
		return logical.ErrorResponse("token_max_ttl must be greater than token_ttl"), nil
	}

	if role.TokenMaxTTL > b.System().MaxLeaseTTL() {
		resp = &logical.Response{}
		resp.AddWarning("token_max_ttl is greater than system or backend mount's max TTL, issued tokens' TTL will be truncated")
	}

	entityID, ok := data.GetOk("entity_id")
	if req.Operation == logical.CreateOperation && !ok {
		return logical.ErrorResponse("entity_id must be provided"), nil
	} else if ok {
		role.EntityID = entityID.(string)
	}

	entityMeta, ok := data.GetOk("entity_meta")
	if ok {
		role.EntityMeta = entityMeta.(map[string]string)
	}

	strictMetaVerify, ok := data.GetOk("strict_meta_verify")
	if req.Operation == logical.CreateOperation && !ok {
		role.StrictMetaVerify = data.GetDefaultOrZero("strict_meta_verify").(bool)
	} else if ok {
		role.StrictMetaVerify = strictMetaVerify.(bool)
	}

	entry, err = logical.StorageEntryJSON(fmt.Sprintf("%s/%s", rolePath, strings.ToLower(roleName)), role)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, roleStorageEntryCreateFailed
	}
	if err = req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return resp, nil
}
