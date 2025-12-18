package sso

import (
	"github.com/adalundhe/micron/auth"
	"github.com/adalundhe/micron/config"
	"github.com/adalundhe/micron/internal/provider"
)



func CreateSSOMiddlewareAndHandlers(
	cfg *config.Config, 
	factory func () auth.SSOClaims,
) (provider.SSO, error) {
	provider, err := provider.NewSSOProvider(cfg.Providers.SSO, cfg.Api, &provider.SSOOpts{
		CreateClaims: factory,
	})
	if err != nil {
		return nil, err
	}

	return provider, nil
}