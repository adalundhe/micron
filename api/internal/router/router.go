package router

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/adalundhe/micron/api/internal/group"
	api "github.com/adalundhe/micron/api/internal/provider"
	"github.com/adalundhe/micron/api/internal/route"
	"github.com/adalundhe/micron/api/internal/variant"
	"github.com/adalundhe/micron/api/routes/service"
	"github.com/gin-gonic/gin"
	"github.com/loopfz/gadgeto/tonic"
	swagger "github.com/num30/gin-swagger-ui"
	"github.com/wI2L/fizz"
	"github.com/wI2L/fizz/openapi"
)

type Router struct {
	BaseUrl     string
	Api         *variant.Variant
	Engine      *gin.Engine
	Spec        *fizz.Fizz
	API         *api.API
	server      *http.Server
	tlsServer   *http.Server
	quitChannel chan os.Signal
	Running     bool
}

type RouterOptions struct {
	TLSPort int
}

func NewRouter(path string, api *api.API) (*Router, error) {
	// Create gin engine without default middleware
	engine := gin.New()

	// Add recovery middleware
	engine.Use(gin.Recovery())

	// Configure GIN's built-in logger to use slog and JSON format
	engine.Use(gin.LoggerWithConfig(gin.LoggerConfig{
		Formatter: func(param gin.LogFormatterParams) string {
			// Log using slog instead of returning a string
			slog.Info("HTTP Request",
				slog.Time("timestamp", param.TimeStamp),
				slog.Int("status", param.StatusCode),
				slog.String("method", param.Method),
				slog.String("path", param.Path),
				slog.String("query", param.Request.URL.RawQuery),
				slog.String("client_ip", param.ClientIP),
				slog.String("user_agent", param.Request.UserAgent()),
				slog.Duration("latency", param.Latency),
				slog.Int("body_size", param.BodySize),
				slog.String("error_message", param.ErrorMessage),
			)
			// Return empty string since we're logging directly with slog
			return ""
		},
	}))

	r := &Router{
		BaseUrl: path,
		Engine:  engine,
		Spec:    fizz.NewFromEngine(engine),
		API:     api,
	}

	return r, nil
}

func (r *Router) AddVariant(
	name string,
	description string,
) *variant.Variant {
	newVariant := variant.NewVariant(name, description)

	variantPath := fmt.Sprintf("/%s", newVariant.Version)
	if r.BaseUrl != "" && r.BaseUrl != "/" {
		variantPath = fmt.Sprintf("%s/%s", r.BaseUrl, newVariant.Version)
	}

	newVariant.SetPath(variantPath)

	r.Api = newVariant

	return newVariant
}

func (r *Router) AddRoute(
	path string,
	method string,
	config route.RouteConfig,
) *route.Route {

	newRoute := route.CreateRoute(
		path,
		method,
		route.RouteConfig{
			Endpoint:   config.Endpoint,
			Spec:       config.Spec,
			Middleware: config.Middleware,
			RawHandler: config.RawHandler,
			StatusCode: config.StatusCode,
		},
	)

	r.addRouteToRouter(newRoute)

	return newRoute

}

func (r *Router) AddGroup(
	path string,
	config group.GroupConfig,
) *group.Group {

	group := group.CreateGroup(
		path,
		group.GroupConfig{
			Description: config.Description,
			Groups:      config.Groups,
			Middleware:  config.Middleware,
			Routes:      config.Routes,
		},
	)

	r.addGroupToRouter(group)

	return group
}

func (r *Router) AddRoutes(routes ...*route.Route) {
	for _, route := range routes {
		r.addRouteToRouter(route)
	}
}

func (r *Router) AddGroups(groups ...*group.Group) {
	for _, subgroup := range groups {
		r.addGroupToRouter(&group.Group{
			Name:        subgroup.Name,
			Path:        fmt.Sprintf("%s/%s", r.BaseUrl, subgroup.Path),
			Description: subgroup.Description,
			Middleware:  subgroup.Middleware,
			Routes:      subgroup.Routes,
			Groups:      subgroup.Groups,
		})
	}
}

func (r *Router) SetDefaults(defaultHandlers service.ServiceDefaults) {
	r.Engine.NoRoute(defaultHandlers.NoRoute...)

	if len(defaultHandlers.NoMethod) > 0 {
		r.Engine.HandleMethodNotAllowed = true
		r.Engine.NoMethod(defaultHandlers.NoMethod...)
	}
}

func (r *Router) SetNoMethod(handlers ...gin.HandlerFunc) {
	r.Engine.NoMethod(handlers...)
}

func (r *Router) AddMiddleware(handlers ...gin.HandlerFunc) {
	r.Engine.Use(handlers...)
}

func (r *Router) Build() {
	r.Api.Group.Build(r.Spec)

}

func (r *Router) EnableOpenAPI() error {

	if r.Api == nil {
		return errors.New("api has not been initialized - please add a variant before calling EnableOpenAPI()")
	}

	infos := &openapi.Info{
		Title:       r.Api.API.Config.Name,
		Description: r.Api.API.Config.Description,
		Version:     r.Api.Version,
	}

	r.Spec.GET("/openapi.json", nil, r.Spec.OpenAPI(infos, "json"))
	swagger.AddOpenApiUIHandler(r.Engine, "/docs", "/openapi.json")

	return nil
}

func (r *Router) TLSIsEnabled(tlsPort int) bool {
	return tlsPort != 0 && r.API.Config.Api.CertPath != "" && r.API.Config.Api.KeyPath != ""
}

func (r *Router) Run(port int, opts *RouterOptions) {

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: r.Engine.Handler(),
	}

	if r.TLSIsEnabled(opts.TLSPort) {
		cert, err := tls.LoadX509KeyPair(r.API.Config.Api.CertPath, r.API.Config.Api.KeyPath)
		if err != nil {
			log.Fatalf("failed to load server certificate and key: %v", err)
		}

		tlsServer := &http.Server{
			Addr:    fmt.Sprintf(":%d", opts.TLSPort),
			Handler: r.Engine.Handler(),
		}

		tlsServer.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}

		r.tlsServer = tlsServer

		slog.Info("Running with TLS certs at paths:", slog.Any("cert_path", r.API.Config.Api.CertPath), slog.Any("key_path", r.API.Config.Api.KeyPath))
		go func() {
			if err := tlsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("listen: %s\n", err)
			}
		}()
	}

	r.server = srv

	go func() {
		r.Running = true
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			r.Running = false
			log.Fatalf("listen: %s\n", err)
		}
	}()
}

func (r *Router) Wait() {

	// Wait for interrupt signal to gracefully shutdown the server with
	// context timeout seconds.
	quit := make(chan os.Signal, 1)

	r.quitChannel = quit
	// kill (no param) default send syscall.SIGTERM
	// kill -2 is syscall.SIGINT
	// kill -9 is syscall. SIGKILL but can"t be catch, so don't need add it
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-r.quitChannel
}

func (r *Router) Shutdown(timeout int) error {

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	log.Println("Shutting down Server ...")
	errs := []error{}

	if err := r.server.Shutdown(ctx); err != nil {
		errs = append(errs, err)
	}

	if err := r.shutDownTLSServer(ctx); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	select {
	case <-ctx.Done():
		log.Println("Met or exceeded timeout.")
	default:
		log.Println("Exited gracefully")
	}
	log.Println("Server exiting")

	r.Running = false

	return nil
}

func (r *Router) shutDownTLSServer(ctx context.Context) error {
	if r.tlsServer == nil {
		return nil
	}

	if err := r.tlsServer.Shutdown(ctx); err != nil {
		return err
	}

	return nil
}

func (r *Router) addGroupToRouter(group *group.Group) {

	newGroup := r.Spec.Group(group.Path, group.Name, group.Description)

	if group.Middleware != nil {
		newGroup.Use(group.Middleware...)
	}

	for _, route := range group.Routes {
		group.AddRouteToGroup(newGroup, route)
	}

	for _, subgroup := range group.Groups {
		subgroup.AddGroupToGroup(newGroup)
	}
}

func (r *Router) addRouteToRouter(route *route.Route) {
	handlers := []gin.HandlerFunc{}

	handlers = append(handlers, route.Middleware...)

	if route.RawHandler == nil && route.StatusCode == 0 {
		route.StatusCode = 200
	}

	if route.RawHandler == nil {
		handlers = append(handlers, tonic.Handler(
			route.Endpoint,
			route.StatusCode,
		))
	}

	if route.Endpoint == nil {
		handlers = append(handlers, route.RawHandler)
	}

	path := fmt.Sprintf("%s/%s", r.BaseUrl, route.Path)

	switch route.Method {
	case "DELETE":
		r.Spec.DELETE(path, route.Spec, handlers...)
	case "GET":
		r.Spec.GET(path, route.Spec, handlers...)

	case "HEAD":
		r.Spec.HEAD(path, route.Spec, handlers...)

	case "OPTIONS":
		r.Spec.OPTIONS(path, route.Spec, handlers...)

	case "PATCH":
		r.Spec.PATCH(path, route.Spec, handlers...)

	case "POST":
		r.Spec.POST(path, route.Spec, handlers...)

	default:
		r.Spec.GET(path, route.Spec, handlers...)

	}

}
