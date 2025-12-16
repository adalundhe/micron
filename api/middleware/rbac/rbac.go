package rbac

import (
	"context"
	"log"

	jwt "github.com/adalundhe/gin-jwt-tonic"
	"github.com/adalundhe/micron/api/auth"
	"github.com/adalundhe/micron/internal/authz"
	"github.com/adalundhe/micron/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/loopfz/gadgeto/tonic"
)

type RBAC struct {
	MiddlewareHandler gin.HandlerFunc
	AuthMiddleware    *jwt.GinJWTMiddleware[*authz.AuthClaims]
}


func RBACMiddleware(
	ctx context.Context,
	cfg *config.Config,
	opts auth.TokenAuthOpts,
) (*RBAC, error) {
	authMiddleware, err := auth.CreateJWTTokenHandler(
		ctx,
		cfg,
		opts,
	)

	if err != nil {
		return nil, err
	}

	tonic.SetErrorHook(jwt.ErrHook)

	return &RBAC{
		MiddlewareHandler: func(context *gin.Context) {
			errInit := authMiddleware.MiddlewareInit()
			if errInit != nil {
				log.Fatal("authMiddleware.MiddlewareInit() Error:" + errInit.Error())
			}
		},
		AuthMiddleware: authMiddleware,
	}, nil
}
