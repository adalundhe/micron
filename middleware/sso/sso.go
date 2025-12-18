package sso

import (
	"github.com/adalundhe/micron/config"
	"github.com/adalundhe/micron/internal/provider"
)


func CreateSSOMiddlewareAndHandlers(cfg *config.Config, opts *provider.SSOOpts) (provider.SSO, error) {
	provider, err := provider.NewSSOProvider(cfg.Providers.SSO, cfg.Api, opts)
	if err != nil {
		return nil, err
	}

	return provider, nil
}