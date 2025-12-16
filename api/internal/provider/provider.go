package provider

import (
	"fmt"

	"github.com/adalundhe/micron/internal/config"
	"github.com/adalundhe/micron/internal/models"
	"github.com/adalundhe/micron/internal/provider"
	"github.com/adalundhe/micron/internal/provider/aws"
	"github.com/adalundhe/micron/internal/provider/idp"
	"github.com/adalundhe/micron/internal/provider/jobs"
	"github.com/adalundhe/micron/internal/stores"
	"github.com/gin-gonic/gin"
	"github.com/uptrace/bun"
)

type APIProviders struct {
	AWS aws.AWSProviderFactory
	Idp idp.IdentityProvider
	JWS provider.JWSProvider
	SSO provider.SSO
}

type APIStores struct {
	Cache    *stores.Cache
	DB       *bun.DB
	Jobs     stores.JobStore
	UserRepo models.UserRepository
}

type API struct {
	Config    *config.Config
	Env       map[string]*config.EnvironmentConfig
	Jobs      jobs.InternalJobManager
	Providers *APIProviders
	Stores    *APIStores
}

func NewApi(apiEnv string) *API {
	return &API{
		Providers: &APIProviders{},
		Stores:    &APIStores{},
		Env:       map[string]*config.EnvironmentConfig{},
	}
}

func (a *API) SetConfig(cfg *config.Config) {
	a.Config = cfg
}

func (a *API) SetProviders(providers *APIProviders) {
	a.Providers = providers
}

func (a *API) SetStores(stores *APIStores) {
	a.Stores = stores
}

func (a *API) SetEnvironment(config map[string]*config.EnvironmentConfig) {

	for key, value := range config {
		a.Env[key] = value
	}
}

func (a *API) SetJobManager(manager jobs.InternalJobManager) {
	a.Jobs = manager
}

func (a *API) GetUserFromContext(ctx *gin.Context) (*models.User, error) {
	user, ok := ctx.Get("user")
	if !ok {
		return nil, fmt.Errorf("user not found in context")
	}

	userObj, ok := user.(*models.User)
	if !ok {
		return nil, fmt.Errorf("unable to cast user to models.User")
	}

	return userObj, nil
}
