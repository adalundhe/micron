package sso

import (
	"github.com/adalundhe/micron/auth"
	"github.com/adalundhe/micron/config"
	micronAuth "github.com/adalundhe/micron/internal/auth"
	"github.com/adalundhe/micron/internal/provider"
	"github.com/adalundhe/micron/service"
)

type Claims interface {}


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

	service.API.SetSSO(provider)
	micronAuth.SSOEnabled = true

	return provider, nil
}