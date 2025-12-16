package auth

import (
	"os"

	"github.com/casbin/casbin/v2"

	"github.com/adalundhe/micron/internal/authz"
	"github.com/adalundhe/micron/internal/config"
	"github.com/adalundhe/micron/internal/provider/idp"
	"github.com/casbin/casbin/v2/model"
	scas "github.com/qiangmzsx/string-adapter/v2"
)

var (
	AuthEnabled = true
	SSOEnabled  = true
)

func Create(
	modelFilepath string,
	policyFilepath string,
	casbinConfig *config.CasbinConfig,
	idpProvider idp.IdentityProvider,
) (*casbin.Enforcer, error) {

	modelText, err := os.ReadFile(modelFilepath)
	if err != nil {
		return nil, err
	}

	policyText, err := os.ReadFile(policyFilepath)
	if err != nil {
		return nil, err
	}

	m, err := model.NewModelFromString(string(modelText))
	if err != nil {
		return nil, err
	}

	// Create a new string adapter
	sa := scas.NewAdapter(string(policyText))

	enforcer, err := casbin.NewEnforcer(m, sa)
	if err != nil {
		return nil, err
	}

	// Set custom role manager
	enforcer.SetRoleManager(authz.NewRoleManager(idpProvider, casbinConfig.ValidEmailDomains, Idp.CheckUserActive))

	// Load policy
	if err := enforcer.LoadPolicy(); err != nil {
		return nil, err
	}

	return enforcer, nil
}
