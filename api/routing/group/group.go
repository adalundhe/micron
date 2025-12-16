package group

import (
	"log/slog"
	"strings"

	"github.com/adalundhe/micron/api/routing/route"
	"github.com/gin-gonic/gin"
	"github.com/loopfz/gadgeto/tonic"
	"github.com/wI2L/fizz"
)

type Group struct {
	Name        string
	Path        string
	Description string
	Groups      []*Group
	Routes      []*route.Route
	Middleware  []gin.HandlerFunc
	RawGroup    *gin.HandlerFunc
}

type GroupConfig struct {
	Description string
	Groups      []*Group
	Routes      []*route.Route
	Middleware  []gin.HandlerFunc
}

func CreateGroup(
	path string,
	config GroupConfig,
) *Group {

	groupName := strings.Replace(
		path,
		"/",
		"",
		-1,
	)

	return &Group{
		Name:        groupName,
		Path:        path,
		Description: config.Description,
		Groups:      config.Groups,
		Routes:      config.Routes,
		Middleware:  config.Middleware,
	}

}

func (g *Group) AddMiddleware(middleware ...gin.HandlerFunc) {
	g.Middleware = append(g.Middleware, middleware...)
}

func (g *Group) AddGroups(groups ...*Group) []*Group {

	for _, group := range groups {

		g.AddGroup(
			group.Path,
			GroupConfig{
				Description: group.Description,
				Groups:      group.Groups,
				Middleware:  group.Middleware,
				Routes:      group.Routes,
			},
		)
	}

	return g.Groups
}

func (g *Group) AddGroup(
	path string,
	config GroupConfig,
) *Group {

	middleware := []gin.HandlerFunc{}
	if len(g.Middleware) > 0 {
		middleware = append(middleware, g.Middleware...)
	}

	if len(config.Middleware) > 0 {
		middleware = append(middleware, config.Middleware...)
	}

	subgroup := CreateGroup(
		path,
		GroupConfig{
			Description: config.Description,
			Groups:      config.Groups,
			Middleware:  middleware,
			Routes:      config.Routes,
		},
	)

	g.Groups = append(g.Groups, subgroup)

	return subgroup
}

func (g *Group) AddRoutes(routes ...*route.Route) []*route.Route {

	for _, newRoute := range routes {
		g.AddRoute(
			newRoute.Path,
			newRoute.Method,
			route.RouteConfig{
				Endpoint:   newRoute.Endpoint,
				Spec:       newRoute.Spec,
				Middleware: newRoute.Middleware,
				RawHandler: newRoute.RawHandler,
				StatusCode: newRoute.StatusCode,
			},
		)
	}

	return g.Routes
}

func (g *Group) AddRoute(
	path string,
	method string,
	config route.RouteConfig,
) *route.Route {

	middleware := []gin.HandlerFunc{}

	if len(g.Middleware) > 0 {
		middleware = append(middleware, g.Middleware...)
	}

	if len(config.Middleware) > 0 {
		middleware = append(middleware, config.Middleware...)
	}

	newRoute := route.CreateRoute(
		path,
		method,
		route.RouteConfig{
			Spec:       config.Spec,
			Endpoint:   config.Endpoint,
			Middleware: middleware,
			RawHandler: config.RawHandler,
			StatusCode: config.StatusCode,
		},
	)

	g.Routes = append(
		g.Routes,
		newRoute,
	)

	return newRoute

}

func (g *Group) Build(spec *fizz.Fizz) *fizz.Fizz {

	var group *fizz.RouterGroup

	if g.RawGroup != nil {
		group = spec.Group(g.Path, g.Name, g.Description, *g.RawGroup)
	} else {
		group = spec.Group(g.Path, g.Name, g.Description)
	}

	if g.Middleware != nil {
		group.Use(g.Middleware...)
	}

	for _, route := range g.Routes {
		g.AddRouteToGroup(group, route)
	}

	for _, subgroup := range g.Groups {
		subgroup.AddGroupToGroup(group)
	}

	return spec
}

func (g *Group) AddGroupToGroup(group *fizz.RouterGroup) {

	var newGroup *fizz.RouterGroup

	if g.RawGroup != nil {
		newGroup = group.Group(g.Path, g.Name, g.Description, *g.RawGroup)
	} else {
		newGroup = group.Group(g.Path, g.Name, g.Description)
	}

	if g.Middleware != nil {
		newGroup.Use(g.Middleware...)
	}

	for _, route := range g.Routes {
		g.AddRouteToGroup(newGroup, route)
	}

	for _, subgroup := range g.Groups {
		subgroup.AddGroupToGroup(newGroup)
	}
}

func (g *Group) AddRouteToGroup(group *fizz.RouterGroup, route *route.Route) {
	slog.Info("GOT:", slog.Any("group", group), slog.Any("route", route.StatusCode))
	handlers := []gin.HandlerFunc{}
	handlers = append(handlers, route.Middleware...)

	if route.RawHandler == nil && route.StatusCode == 0 {
		route.StatusCode = 200
	}

	if route.RawHandler != nil {
		handlers = append(handlers, route.RawHandler)
	} else {
		handlers = append(handlers, tonic.Handler(
			route.Endpoint,
			route.StatusCode,
		))
	}

	switch route.Method {
	case "DELETE":
		group.DELETE(route.Path, route.Spec, handlers...)
	case "GET":
		group.GET(route.Path, route.Spec, handlers...)

	case "HEAD":
		group.HEAD(route.Path, route.Spec, handlers...)

	case "OPTIONS":
		group.OPTIONS(route.Path, route.Spec, handlers...)

	case "PATCH":
		group.PATCH(route.Path, route.Spec, handlers...)

	case "POST":
		group.POST(route.Path, route.Spec, handlers...)

	default:
		group.GET(route.Path, route.Spec, handlers...)

	}

}
