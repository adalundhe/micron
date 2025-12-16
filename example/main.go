package main

import (
	"context"
	"log"

	"github.com/adalundhe/micron/api"
	"github.com/adalundhe/micron/api/routing/route"
	"github.com/adalundhe/micron/api/routing/router"
	"github.com/adalundhe/micron/api/service"
	"github.com/adalundhe/micron/internal/config"
	"github.com/gin-gonic/gin"
)


func main() {


	service, err := api.Create(&api.App{
		Build: func(ctx context.Context, routes *router.Router, api *service.Service, cfg *config.Config) (*router.Router, error) {

			test := routes.CreateRoute("/test", "GET", router.RouteConfig{
				Endpoint: func(ctx *gin.Context) (string, error) {
					return "Hello!", nil
				},
				StatusCode: 200,
			})


			routes.AddVariant("v1", "A test api.", &router.Routes{
				Endpoints: []*route.Route{test},
			})

			return routes, nil
		},
	})

	if err != nil {
		log.Fatalf("Encoutnered error creating API - %s", err.Error())
	}

	if err := service.Run("test", "A test server"); err != nil {
		log.Fatalf("Encountered error while running - %s", err.Error())
	}
}

