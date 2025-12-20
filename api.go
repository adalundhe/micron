package micron

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/adalundhe/micron/auth"
	"github.com/adalundhe/micron/config"
	"github.com/adalundhe/micron/internal"
	"github.com/adalundhe/micron/otel"
	"github.com/adalundhe/micron/provider"
	"github.com/adalundhe/micron/provider/aws"
	"github.com/adalundhe/micron/provider/idp"
	"github.com/adalundhe/micron/provider/jobs"
	"github.com/adalundhe/micron/routes"
	"github.com/adalundhe/micron/stores"
	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"github.com/uptrace/bun"
)

var (
	Providers *internal.ServiceProviders
	Stores *internal.ServiceStores
	Service *internal.Service
	DB *bun.DB
	Cache *stores.Cache
	Config *config.Config
)

type RunOptions struct {
	ShortDescription string
	LongDescription string
}

type AuthOptions struct {
	CreateSSOClaims	  func() interface{}
	IDPFactory        func(ctx context.Context, cfg *config.Config, cache stores.Cache, providers *providerConfig, awsProviderFactory aws.AWSProviderFactory) (idp.IdentityProvider, error)
	IDPEnabled        bool
	RBACModelPath     string
	RBACPolicyPath    string
}

type SeverOptions struct {
	Name              string
	Description       string
	Version           string
	Port              int
	TLSPort           int
	HealthCheckPort   int
	ConfigPath        string
	LogLevel          string
}

type ProviderOptions struct {
	Enabled  []string
}

type App struct {
	Auth 	  		  *AuthOptions 
	Server 		  	  *SeverOptions  
	Providers 		  *ProviderOptions

	Build             func(ctx context.Context, router *routes.Router, cfg *config.Config) (*routes.Router, error)

	cfg *config.Config
	runCmd *cobra.Command
}


func loadAppDefaults(app *App) (*App, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	if app.Build == nil {
		log.Fatalf("Err. - Build function required")
	}

	if app.Server.ConfigPath == "" {
		app.Server.ConfigPath = path.Join(cwd, "config.yml")
	}

	if app.Server.HealthCheckPort == 0 {
		app.Server.HealthCheckPort = 9081
	}

	if app.Auth.IDPEnabled && app.Auth.IDPFactory == nil {
		log.Fatalf("Err. - IDP is enabled and IDP Factory not specified but required")
	}

	if app.Server.LogLevel == "" {
		app.Server.LogLevel = "info"
	}

	if app.Auth.RBACModelPath == "" {
		app.Auth.RBACModelPath = path.Join(cwd, "model.conf")
	}

	if app.Auth.RBACPolicyPath == "" {
		app.Auth.RBACPolicyPath = path.Join(cwd, "policy.csv")
	}

	if app.Server.Port == 0 {
		app.Server.Port = 8081
	}

	if app.Server.TLSPort == 0 {
		app.Server.TLSPort = 8443
	}

	return app, nil
}

func loadConfig(app *App) (*config.Config, error) {
	configPath := app.Server.ConfigPath
	if configPath == "" {
		configPath = os.Getenv("CONFIG_PATH")

	}

	cfg, err := config.LoadConfigFromPath(configPath)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func createCache(
	ctx context.Context,
	cfg *config.Config,
	awsProviderFactory aws.AWSProviderFactory,
) (stores.Cache, error) {

	var cache stores.Cache
	var err error

	if awsProviderFactory == nil {
		slog.Info("Creating cache without AWS provider")
		cache, err = stores.NewCache(
			ctx,
			*cfg.Cache,
		)
	} else {
		slog.Info("Creating cache with AWS provider")
		cache, err = stores.NewCache(
			ctx,
			*cfg.Cache,
			func(rco *provider.RedisConfigOpt) {
				rco.AWSProviderFactory = awsProviderFactory
			},
		)
	}

	if err != nil {
		return nil, err
	}

	return cache, err
}

func createDb(databaseConfig *config.DatabaseConfig) (*bun.DB, error) {
	dbConn, err := stores.NewDB(
		databaseConfig.Type,
		databaseConfig.DSN,
		databaseConfig.Username,
		databaseConfig.Password,
	)

	if err != nil {
		return nil, err
	}

	return dbConn, nil
}

func createEnforcer(
	app *App,
	casbinConfig *config.CasbinConfig,
	idpProvider idp.IdentityProvider,
) (*casbin.Enforcer, error) {
	modelFilepath := app.Auth.RBACModelPath
	if modelFilepath == "" {
		modelFilepath = os.Getenv("AUTH_MODEL_PATH")
	}

	policyFilepath := app.Auth.RBACPolicyPath
	if policyFilepath == "" {
		policyFilepath = os.Getenv("AUTH_POLICY_PATH")
	}

	enforcer, err := auth.Create(
		modelFilepath,
		policyFilepath,
		casbinConfig,
		idpProvider,
	)

	if err != nil {
		return nil, err
	}

	return enforcer, nil
}

func setupApi(
	ctx context.Context,
	cfg *config.Config,
	apiService *internal.Service,
	providers *providerConfig,
	app *App,
) (*routes.Router, error) {

	if app.Server.Name == "" {
		app.Server.Name = cfg.Name
	}

	if app.Server.Description == "" {
		app.Server.Description = cfg.Description
	}

	if app.Server.Version == "" {
		app.Server.Version = cfg.Version
	}

	providers.AddEnabledProviders(cfg.Providers.EnabledProviders)

	err := otel.SetupOTelSDK(ctx, config.NewBuildInfo(app.Server.Name, app.Server.Version))
	if err != nil {
		return nil, fmt.Errorf("failed to setup opentelemetry: %w", err)
	}

	dbConn, err := createDb(cfg.Database)
	if err != nil {
		return nil, err
	}

	auth.DB = dbConn

	awsProviderFactory := providers.Overrides.AWS

	if providers.Overrides.AWS == nil && providers.IsEnabled("AWS") {
		slog.Info("AWS provider enabled")
		awsProviderFactory = aws.NewAwsProviderFactory(
			ctx,
			cfg.Providers.Aws,
		)
	}

	cache, err := createCache(ctx, cfg, awsProviderFactory)
	if err != nil {
		return nil, err
	}

	dbUserRepo := stores.NewDbUserRepository(dbConn)

	stores.Users = dbUserRepo
	jobStore := stores.NewJobStore(dbConn)

	Cache = &cache
	DB = dbConn

	apiService.SetStores(&internal.ServiceStores{
		Cache:    &cache,
		DB:       dbConn,
		Jobs:     jobStore,
		UserRepo: dbUserRepo,
	})

	var idpProvider idp.IdentityProvider
	if app.Auth.IDPEnabled {
		idpProvider, err = app.Auth.IDPFactory(ctx, cfg, cache, providers, awsProviderFactory)
	}

	if err != nil {
		return nil, err
	}

	// Set the IDP provider in auth package
	auth.Idp = idpProvider

	jwsProvider := providers.Overrides.JWS
	if providers.Overrides.JWS == nil && providers.IsEnabled("jws") {
		slog.Info("JWS provider enabled")
		jwsProvider, err = provider.NewJWSProviderFromEnvironments(cfg.DeployEnvs)
	}

	if err != nil {
		return nil, err
	}

	auth.SSOEnabled = false

	ssoProvider := providers.Overrides.SSO
	if providers.Overrides.SSO == nil && providers.IsEnabled("sso") {
		ssoProvider, err = provider.NewSSOProvider(cfg.Providers.SSO, cfg.Api, &provider.SSOOpts{
			CreateClaims: app.Auth.CreateSSOClaims,
		})
	}
	if err != nil {
		return nil, err
	}

	if ssoProvider == nil {
		auth.SSOEnabled = false
	}

	apiService.SetProviders(&internal.ServiceProviders{
		AWS: awsProviderFactory,
		Idp: idpProvider,
		JWS: jwsProvider,
	})

	expandedEnvs, err := cfg.ExpandDeploymentEnvs(http.DefaultClient)
	if err != nil {
		return nil, err
	}

	apiService.SetEnvironment(expandedEnvs)
	apiService.SetConfig(cfg)

	jobManager := jobs.NewInternalJobManager(ctx, cache.GetRedisClient(), jobStore)
	apiService.SetJobManager(jobManager)

	enforcer := providers.Overrides.Auth
	auth.AuthEnabled = providers.IsEnabled("auth")
	if providers.Overrides.Auth == nil && auth.AuthEnabled {
		enforcer, err = createEnforcer(app, cfg.Providers.Casbin, idpProvider)
		apiService.Providers.Casbin = enforcer
	}

	if err != nil {
		return nil, err
	}

	if !auth.AuthEnabled {
		slog.Warn("Warning - auth is enabled - this should be done for debugging or development purposes only!")
	}

	auth.Enforcer = enforcer

	router, err := routes.NewRouter("/api", apiService)
	if err != nil {
		return nil, err
	}

	router.SetNoMethod()
	router.SetDefaults(routes.CreateDefaultHandlers())

	Service = router.Api.Service
	Providers = router.Service.Providers
	Stores = router.Service.Stores
	Config = cfg
	

	if router, err = app.Build(
		ctx,
		router,
		cfg,
	); err != nil {
		return nil, err
	}

	if router.Api == nil {
		router.Api = router.AddVariant(
			app.Server.Version, 
			app.Server.Description,
			&routes.Routes{
				Groups: router.Groups,
				Endpoints: router.Routes,
			},
		)
	} else {
		
		router.Api.AddGroups(router.Groups...)
		router.Api.AddRoutes(router.Routes...)

	}

	err = router.EnableOpenAPI()
	if err != nil {
		return nil, err
	}

	router.Build()

	return router, nil
}

func createHealthCheckApi(api *internal.Service) (*routes.Router, error) {
	healthCheckApi, err := routes.NewRouter("/", api)
	if err != nil {
		return nil, err
	}

	healthCheckApi.AddRoute(
		"/health",
		"GET",
		routes.RouteConfig{
			Endpoint: func(c *gin.Context) (string, error) {
				return "OK", nil
			},
			StatusCode: 200,
		},
	)

	healthCheckApi.SetNoMethod()
	healthCheckApi.SetDefaults(routes.CreateDefaultHandlers())

	return healthCheckApi, nil

}

func runServers(
	api *routes.Router,
	healthCheckApi *routes.Router,
) {
	var wg sync.WaitGroup

	// This has to be equal to the number of servers
	// or we get a negative wait counter violation
	wg.Add(2)

	errChan := make(chan error, 1)

	go func() {
		defer wg.Done()
		api.Wait()
		errChan <- api.Shutdown(10)
	}()

	go func() {
		defer wg.Done()
		healthCheckApi.Wait()
		errChan <- healthCheckApi.Shutdown(10)
	}()

	go func() {
		wg.Wait()
		close(errChan)
	}()

	err := <-errChan
	if err != nil {
		slog.Error("API encountered error starting", slog.String("error", err.Error()))
	}

	slog.Info("API shutdown complete")
}

func Create(app *App) (*App, error) {

	app, err := loadAppDefaults(app)
	if err != nil {
		return nil, err
	}

	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run the server",
		Long: fmt.Sprintf(
			`Starts and runs the API on the provided or default
		port (%d).`,
			app.Server.Port,
		),
		Run: func(cmd *cobra.Command, args []string) {

			cfg, err := loadConfig(app)
			if err != nil {
				log.Fatalf("Encountered error loading config - %s", err.Error())
			}

			if err := cfg.Validate(); err != nil {
				log.Fatalf("Encountered error validating config - %s", err.Error())
			}

			app.cfg = cfg


			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			if err != nil {
				log.Fatalf("error loading config - %s", err)
			}

			apiService := internal.NewService(app.cfg.Api.Env)
			srv, err := setupApi(
				ctx,
				app.cfg,
				apiService,
				createProviderConfig(
					app.Providers.Enabled,
				),
				app,
			)

			if err != nil {
				log.Fatalf("encountered error - %s", err)
			}

			healthCheckServer, err := createHealthCheckApi(srv.Service)
			if err != nil {
				log.Fatalf("encountered error starting healthcheck API - %s", err)
			}

			srv.Run(app.Server.Port, &routes.RouterOptions{
				TLSPort: app.Server.TLSPort,
			})

			healthCheckServer.Run(app.Server.HealthCheckPort, &routes.RouterOptions{})

			runServers(srv, healthCheckServer)
		},
	}

	runCmd.Flags().IntVarP(&app.Server.Port, "port", "p", app.Server.Port, "Set server port")
	runCmd.Flags().IntVarP(&app.Server.TLSPort, "tls-port", "t", app.Server.TLSPort, "Set server port")
	runCmd.Flags().IntVarP(&app.Server.HealthCheckPort, "check-port", "c", app.Server.HealthCheckPort, "Set server port")
	runCmd.Flags().StringVarP(&app.Server.ConfigPath, "config", "C", "config.yml", "Path to the config.yaml")
	runCmd.Flags().StringVarP(&app.Auth.RBACModelPath, "model", "M", "model.conf", "Path to the Casbin model.conf")
	runCmd.Flags().StringVarP(&app.Auth.RBACPolicyPath, "policy", "P", "policy.csv", "Path to the Casbin policy.csv")
	runCmd.Flags().StringArrayVarP(&app.Providers.Enabled, "disable", "d", []string{}, "A comma-delimited list of providers to disable")
	runCmd.Flags().StringVarP(&app.Server.LogLevel, "log-level", "l", "info", "Set server log level")
	runCmd.Flags().StringVarP(&app.Server.Version, "version", "v", "v1", "Set the API version")

	app.runCmd = runCmd

	return app, nil
}

func (a *App) Run(loader func() error,altDescriptors ...string) error {

	if err := loader(); err != nil {
		return err
	}

	altDescriptor := ""
	if len(altDescriptors) > 0 {
		altDescriptor = altDescriptors[0]
	}
	

	rootCmd := &cobra.Command{
		Use:   strings.ToLower(a.Server.Name),
		Short: a.Server.Description,
		Long: altDescriptor,
	}


	rootCmd.AddCommand(a.runCmd)

	return rootCmd.Execute()

}
