package service

import (
	"fmt"

	"github.com/adalundhe/micron/config"
	"github.com/adalundhe/micron/internal/models"
	"github.com/adalundhe/micron/internal/provider"
	"github.com/adalundhe/micron/internal/provider/aws"
	"github.com/adalundhe/micron/internal/provider/idp"
	"github.com/adalundhe/micron/internal/provider/jobs"
	"github.com/adalundhe/micron/internal/stores"
	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
	"github.com/uptrace/bun"
)

type ServiceProviders struct {
	AWS		aws.AWSProviderFactory
	Idp		idp.IdentityProvider
	JWS		provider.JWSProvider
	SSO		provider.SSO
	Casbin  *casbin.Enforcer
}

type ServiceStores struct {
	Cache    *stores.Cache
	DB       *bun.DB
	Jobs     stores.JobStore
	UserRepo models.UserRepository
}

type Service struct {
	Config    *config.Config
	Env       map[string]*config.EnvironmentConfig
	Jobs      jobs.InternalJobManager
	Providers *ServiceProviders
	Stores    *ServiceStores
}

var API *Service
var DB *bun.DB
var Cache *stores.Cache
var Jobs stores.JobStore

func NewService(apiEnv string) *Service {
	return &Service{
		Providers: &ServiceProviders{},
		Stores:    &ServiceStores{},
		Env:       map[string]*config.EnvironmentConfig{},
	}
}

func (a *Service) SetConfig(cfg *config.Config) {
	a.Config = cfg
}

func (a *Service) SetProviders(providers *ServiceProviders) {
	a.Providers = providers
}

func (a *Service) SetSSO(sso provider.SSO) {
	a.Providers.SSO = sso
}

func (a *Service) SetStores(stores *ServiceStores) {
	a.Stores = stores
}

func (a *Service) SetEnvironment(config map[string]*config.EnvironmentConfig) {

	for key, value := range config {
		a.Env[key] = value
	}
}

func (a *Service) SetJobManager(manager jobs.InternalJobManager) {
	a.Jobs = manager
}

func (a *Service) GetUserFromContext(ctx *gin.Context) (*models.User, error) {
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
