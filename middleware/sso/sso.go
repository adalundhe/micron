package sso

import (
	micronAuth "github.com/adalundhe/micron/auth"
	"github.com/adalundhe/micron/config"
	"github.com/adalundhe/micron/internal"
	"github.com/adalundhe/micron/provider"
)

type Claims interface {}


func CreateSSOMiddlewareAndHandlers(
	cfg *config.Config, 
	factory func () interface{},
) (provider.SSO, error) {
	provider, err := provider.NewSSOProvider(cfg.Providers.SSO, cfg.Api, &provider.SSOOpts{
		CreateClaims: factory,
	})
	if err != nil {
		return nil, err
	}

	internal.InternalAPI.SetSSO(provider)
	micronAuth.SSOEnabled = true

	return provider, nil
}