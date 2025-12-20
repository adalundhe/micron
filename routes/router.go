package routes

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

	"github.com/adalundhe/micron/internal"
	"github.com/gin-gonic/gin"
	"github.com/loopfz/gadgeto/tonic"
	swagger "github.com/num30/gin-swagger-ui"
	"github.com/wI2L/fizz"
	"github.com/wI2L/fizz/openapi"
)

type Router struct {
	BaseUrl     string
	Api         *Variant
	Engine      *gin.Engine
	Spec        *fizz.Fizz
	Service      *internal.Service
	server      *http.Server
	tlsServer   *http.Server
	quitChannel chan os.Signal
	Running     bool
	Groups 		[]*Group
	Routes 		[]*Route
}

type RouterOptions struct {
	TLSPort int
}

type RouteConfig struct {
	Endpoint   interface{}
	Spec       []fizz.OperationOption
	Middleware []gin.HandlerFunc
	RawHandler gin.HandlerFunc
	StatusCode int
}

type GroupConfig struct {
	Description string
	Groups      []*Group
	Routes      []*Route
	Middleware  []gin.HandlerFunc
}

type Routes struct {
	Groups []*Group
	Endpoints []*Route
	Middleware []gin.HandlerFunc
}


func NewRouter(path string, service *internal.Service) (*Router, error) {
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
		Service:     service,
	}

	return r, nil
}

func (r *Router) CreateRoute(
	path string,
	method string,
	config RouteConfig,
) *Route {


	return CreateRoute(
		path,
		method,
		RouteConfig{
			Endpoint:   config.Endpoint,
			Spec:       config.Spec,
			Middleware: config.Middleware,
			RawHandler: config.RawHandler,
			StatusCode: config.StatusCode,
		},
	)
}

func (r *Router) CreateGroup(
	path string,
	config GroupConfig,
) *Group {
	return  CreateGroup(
		path,
		GroupConfig{
			Description: config.Description,
			Groups:      config.Groups,
			Middleware:  config.Middleware,
			Routes:      config.Routes,
		},
	)
}

func (r *Router) AddVariant(
	name string,
	description string,
	routes *Routes,
) *Variant {
	newVariant := NewVariant(name, description)

	variantPath := fmt.Sprintf("/%s", newVariant.Version)
	if r.BaseUrl != "" && r.BaseUrl != "/" {
		variantPath = fmt.Sprintf("%s/%s", r.BaseUrl, newVariant.Version)
	}

	newVariant.SetPath(variantPath)

	if len(routes.Groups) > 0 {
		newVariant.AddGroups(routes.Groups...)
	}

	if len(routes.Endpoints) > 0 {
		newVariant.AddRoutes(routes.Endpoints...)
	}

	if len(routes.Middleware) > 0 {
		newVariant.AddMiddleware(routes.Middleware...)
	}

	r.Api = newVariant
	r.Api.setService(r.Service)


	return newVariant
}

func (r *Router) AddRoute(
	path string,
	method string,
	config RouteConfig,
) *Route {

	newRoute := CreateRoute(
		path,
		method,
		RouteConfig{
			Endpoint:   config.Endpoint,
			Spec:       config.Spec,
			Middleware: config.Middleware,
			RawHandler: config.RawHandler,
			StatusCode: config.StatusCode,
		},
	)

	r.Routes = append(r.Routes, newRoute)

	return newRoute

}

func (r *Router) AddGroup(
	path string,
	config GroupConfig,
) *Group {

	group := CreateGroup(
		path,
		GroupConfig{
			Description: config.Description,
			Groups:      config.Groups,
			Middleware:  config.Middleware,
			Routes:      config.Routes,
		},
	)

	r.Groups = append(r.Groups, group)

	return group
}

func (r *Router) AddRoutes(routes ...*Route) {
	for _, route := range routes {
		r.addRouteToRouter(route)
	}
}

func (r *Router) AddGroups(groups ...*Group) {
	for _, subgroup := range groups {
		r.addGroupToRouter(&Group{
			Name:        subgroup.Name,
			Path:        fmt.Sprintf("%s/%s", r.BaseUrl, subgroup.Path),
			Description: subgroup.Description,
			Middleware:  subgroup.Middleware,
			Routes:      subgroup.Routes,
			Groups:      subgroup.Groups,
		})
	}
}

func (r *Router) SetDefaults(defaultHandlers ServiceDefaults) {
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
		Title:       r.Api.Service.Config.Name,
		Description: r.Api.Service.Config.Description,
		Version:     r.Api.Version,
	}

	r.Spec.GET("/openapi.json", nil, r.Spec.OpenAPI(infos, "json"))
	swagger.AddOpenApiUIHandler(r.Engine, "/docs", "/openapi.json")

	return nil
}

func (r *Router) TLSIsEnabled(tlsPort int) bool {
	return tlsPort != 0 && r.Service.Config.Api.CertPath != "" && r.Service.Config.Api.KeyPath != ""
}

func (r *Router) Run(port int, opts *RouterOptions) {

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: r.Engine.Handler(),
	}

	if r.TLSIsEnabled(opts.TLSPort) {
		cert, err := tls.LoadX509KeyPair(r.Service.Config.Api.CertPath, r.Service.Config.Api.KeyPath)
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

		slog.Info("Running with TLS certs at paths:", slog.Any("cert_path", r.Service.Config.Api.CertPath), slog.Any("key_path", r.Service.Config.Api.KeyPath))
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

func (r *Router) addGroupToRouter(group *Group) {

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

func (r *Router) addRouteToRouter(route *Route) {
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
