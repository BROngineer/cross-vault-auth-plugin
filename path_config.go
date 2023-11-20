package cva

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configHelpSynopsis    = "Configures target Vault cluster API information"
	configHelpDescription = `
The Cross Vault Auth Backend validates token, issued by the target 
Vault cluster using token lookup capability. It ensures, that the 
token is valid and matches provided role configuration: entity ID 
and it's metadata.`
)

type crossVaultAuthBackendConfig struct {
	// Cluster stores the address of the target Vault cluster
	Cluster string `json:"cluster"`

	// CACert stores CA certificate to validate target Vault cluster's cert
	CACert string `json:"ca_cert"`

	// InsecureSkipVerify defines whether to skip TLS verification
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
}

func (b *crossVaultAuthBackend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config$",
		Fields: map[string]*framework.FieldSchema{
			"cluster": {
				Type: framework.TypeString,
				Description: `Cluster must contain value of a Vault cluster endpoint
					should be a hostname, host:port pair, or a URL`,
			},
			"ca_cert": {
				Type:        framework.TypeString,
				Description: "PEM encoded CA cert to be used by HTTP client",
			},
			"insecure_skip_verify": {
				Type:        framework.TypeBool,
				Default:     false,
				Description: "Flag defines whether to skip TLS verification",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "read",
				},
				Description: "returns stored configuration",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "write",
				},
				Description: "writes configuration",
			},
		},
		HelpSynopsis:    configHelpSynopsis,
		HelpDescription: configHelpDescription,
	}
}

func (b *crossVaultAuthBackend) pathConfigRead(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"cluster":              config.Cluster,
			"ca_cert":              config.CACert,
			"insecure_skip_verify": config.InsecureSkipVerify,
		},
	}, nil
}

func (b *crossVaultAuthBackend) pathConfigWrite(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	var (
		entry *logical.StorageEntry
		err   error
	)

	b.mu.Lock()
	defer b.mu.Unlock()

	cluster := data.Get("cluster").(string)
	if cluster == "" {
		return logical.ErrorResponse("cluster must be provided"), nil
	}
	caCert := data.Get("ca_cert").(string)
	insecureSkipVerify := data.Get("insecure_skip_verify").(bool)

	config := &crossVaultAuthBackendConfig{
		Cluster:            cluster,
		CACert:             caCert,
		InsecureSkipVerify: insecureSkipVerify,
	}

	if err = b.updateTLSConfig(config); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	entry, err = logical.StorageEntryJSON(configPath, config)
	if err != nil {
		return nil, err
	}

	if err = req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}
