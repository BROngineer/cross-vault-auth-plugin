package main

import (
	"os"

	cva "github.com/brongineer/cross-vault-auth-plugin"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

var logger hclog.Logger

func init() {
	logger = hclog.New(&hclog.LoggerOptions{
		Name:       "cross-vault-auth-plugin",
		Level:      2,
		JSONFormat: true,
	})
}

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	err := flags.Parse(os.Args[1:])
	if err != nil {
		logger.Error("plugin shutdown", "error", err)
		os.Exit(1)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)
	err = plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: cva.Factory,
		TLSProviderFunc:    tlsProviderFunc,
		Logger:             logger,
	})
	if err != nil {
		logger.Error("plugin shutdown", "error", err)
		os.Exit(1)
	}
}
