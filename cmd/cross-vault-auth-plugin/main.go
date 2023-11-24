package main

import (
	"os"

	cva "github.com/brongineer/cross-vault-auth-plugin"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	// default logger to log errors on plugin startup
	logger := hclog.New(&hclog.LoggerOptions{})

	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	err := flags.Parse(os.Args[1:])
	if err != nil {
		logger.Error("failed to parse arguments, plugin shutdown", "error", err)
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
		logger.Error("failed to start serve, plugin shutdown", "error", err)
		os.Exit(1)
	}
}
