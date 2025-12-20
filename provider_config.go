package micron

import (
	"strings"

	"github.com/adalundhe/micron/provider"
	"github.com/adalundhe/micron/provider/aws"
	"github.com/adalundhe/micron/provider/idp"
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
	enabledProviders []string
	Overrides         *overrideProviders
}

func (p *providerConfig) IsEnabled(providerName string) bool {

	for _, enabledProvider := range p.enabledProviders {
		if strings.EqualFold(providerName, enabledProvider) {
			return true
		}
	}

	return false

}

func (p *providerConfig) AddEnabledProviders(providerNames []string) {
	for _, providerName := range providerNames {
		if providerName != "" {
			p.appendProviderIfNotExists(providerName)
		}
	}
}

func (p *providerConfig) appendProviderIfNotExists(providerName string) {

	for _, enabledProvider := range p.enabledProviders {
		if strings.EqualFold(providerName, enabledProvider) {
			return
		}
	}

	if providerName != "" {
		p.enabledProviders = append(p.enabledProviders, providerName)
	}

}

func createProviderConfig(providerNames []string) *providerConfig {

	loweredProviderNames := []string{}

	for _, name := range providerNames {
		if name != "" {
			loweredProviderNames = append(
				loweredProviderNames,
				strings.ToLower(name),
			)
		}
	}

	return &providerConfig{
		enabledProviders: loweredProviderNames,
		Overrides:         &overrideProviders{},
	}

}
