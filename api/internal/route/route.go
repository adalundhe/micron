package route

import (
	"github.com/gin-gonic/gin"
	"github.com/wI2L/fizz"
)

type Route struct {
	Path       string
	Method     string
	Endpoint   interface{}
	Spec       []fizz.OperationOption
	RawHandler gin.HandlerFunc
	Middleware []gin.HandlerFunc
	StatusCode int
}

type RouteConfig struct {
	Endpoint   interface{}
	Spec       []fizz.OperationOption
	Middleware []gin.HandlerFunc
	RawHandler gin.HandlerFunc
	StatusCode int
}

func CreateRoute(
	path string,
	method string,
	config RouteConfig,
) *Route {
	middleware := []gin.HandlerFunc{}

	if len(config.Middleware) > 0 {
		middleware = append(middleware, config.Middleware...)
	}

	return &Route{
		Path:       path,
		Method:     method,
		Endpoint:   config.Endpoint,
		Middleware: middleware,
		Spec:       config.Spec,
		RawHandler: config.RawHandler,
		StatusCode: config.StatusCode,
	}
}

func (r *Route) AddMiddleware(middleware ...gin.HandlerFunc) {
	r.Middleware = append(r.Middleware, middleware...)
}
