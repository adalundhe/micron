package api

import (
	"strings"

	"github.com/adalundhe/micron/internal/provider"
	"github.com/adalundhe/micron/internal/provider/aws"
	"github.com/adalundhe/micron/internal/provider/idp"
	"github.com/casbin/casbin/v2"
)

type overrideProviders struct {
	IDP  idp.IdentityProvider // For overriding the entire IDP shim
	AWS  aws.AWSProviderFactory
	JWS  provider.JWSProvider
	Auth *casbin.Enforcer
	SSO  provider.SSO
}

type providerConfig struct {
	disabledProviders []string
	Overrides         *overrideProviders
}

func (p *providerConfig) IsEnabled(providerName string) bool {

	for _, disabledProvider := range p.disabledProviders {
		if strings.EqualFold(providerName, disabledProvider) {
			return false
		}
	}

	return true

}

func (p *providerConfig) AddDisabledProviders(providerNames []string) {
	for _, providerName := range providerNames {
		p.appendProviderIfNotExists(providerName)
	}
}

func (p *providerConfig) appendProviderIfNotExists(providerName string) {

	for _, disabledProvider := range p.disabledProviders {
		if strings.EqualFold(providerName, disabledProvider) {
			return
		}
	}

	p.disabledProviders = append(p.disabledProviders, providerName)

}

func createProviderConfig(providerNames []string) *providerConfig {

	loweredProviderNames := []string{}

	for _, name := range providerNames {
		loweredProviderNames = append(
			loweredProviderNames,
			strings.ToLower(name),
		)
	}

	return &providerConfig{
		disabledProviders: loweredProviderNames,
		Overrides:         &overrideProviders{},
	}

}
