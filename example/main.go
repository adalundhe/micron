package main

import (
	"context"
	"log"

	"github.com/adalundhe/micron/api"
	"github.com/adalundhe/micron/api/routing/router"
	"github.com/adalundhe/micron/api/service"
	"github.com/adalundhe/micron/internal/config"
	"github.com/gin-gonic/gin"
)


func main() {


	service, err := api.Create(&api.App{
		Build: func(ctx context.Context, routes *router.Router, api *service.Service, cfg *config.Config) error {

			routes.CreateRoute("/test", "GET", router.RouteConfig{
				Endpoint: func(ctx *gin.Context) string {
					return "Hello!"
				},
				StatusCode: 200,
			})

			return nil
		},
	})

	if err != nil {
		log.Fatalf("Encoutnered error creating API - %s", err.Error())
	}

	if err := service.Run("test", "A test server"); err != nil {
		log.Fatalf("Encountered error while running - %s", err.Error())
	}
}

