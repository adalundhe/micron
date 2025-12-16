package service

import (
	"github.com/adalundhe/micron/api/internal/group"
	"github.com/adalundhe/micron/api/internal/route"
	"github.com/gin-gonic/gin"
)

type StatusResponse struct {
	Message string `json:"message"`
}

type ServiceDefaults struct {
	NoRoute  []gin.HandlerFunc
	NoMethod []gin.HandlerFunc
}

func CreateDefaultHandlers() ServiceDefaults {
	return ServiceDefaults{
		NoMethod: []gin.HandlerFunc{
			func(c *gin.Context) {
				c.JSON(405, gin.H{"code": "METHOD_NOT_ALLOWED", "message": "Method not allowed"})
			},
		},
		NoRoute: []gin.HandlerFunc{
			func(c *gin.Context) {
				c.JSON(404, gin.H{"code": "PAGE_NOT_FOUND", "message": "Page not found"})
			},
		},
	}
}

func Status(c *gin.Context) (*StatusResponse, error) {
	return &StatusResponse{
		Message: "Hello from Micron!",
	}, nil
}

func CreateServiceRoutes() *group.Group {

	serviceRoutes := group.CreateGroup(
		"/service",
		group.GroupConfig{},
	)

	serviceRoutes.AddRoutes(
		route.CreateRoute(
			"/status",
			"GET",
			route.RouteConfig{
				Endpoint:   Status,
				StatusCode: 200,
			},
		),
	)

	return serviceRoutes
}
