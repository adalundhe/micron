package rbac

import (
	"context"
	"log"
	"time"

	jwt "github.com/adalundhe/gin-jwt-tonic"
	"github.com/adalundhe/micron/internal/auth"
	"github.com/adalundhe/micron/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/loopfz/gadgeto/tonic"
)

type RBAC[T interface{}] struct {
	MiddlewareHandler gin.HandlerFunc
	AuthMiddleware    *jwt.GinJWTMiddleware[T]
}

type Auth[T interface{}] struct {
	Validator func(data interface{}, c *gin.Context) bool
	MapToClaims func(data interface{}) (T, error)
	Authorize func (claims T, allowed map[string][]string) (string, error)
	SigningAlgorithm string
	IdentityKey string
	Realm string
	Timeout time.Duration
	MaxRefresh time.Duration
	TokenLookup string
	TokenHeadName string
	Allowed map[string][]string
	IdentifierKey string
}


func RBACMiddleware[T interface{}](
	ctx context.Context,
	cfg *config.Config,
	authenticator Auth[T],
) (*RBAC[T], error) {

	opts := &auth.TokenAuth[T]{
		Validator: authenticator.Validator,
		MapToClaims: authenticator.MapToClaims,
		Authorize: authenticator.Authorize,
		SigningAlgorithm: authenticator.SigningAlgorithm,
		IdentityKey: authenticator.IdentityKey,
		Realm: authenticator.Realm,
		Timeout: authenticator.Timeout,
		MaxRefresh: authenticator.MaxRefresh,
		TokenLookup: authenticator.TokenLookup,
		TokenHeadName: authenticator.TokenHeadName,
		Allowed: authenticator.Allowed,
		IdentifierKey: authenticator.IdentifierKey,
	}


	authMiddleware, err := opts.CreateHandler(
		ctx,
		cfg,
	)

	if err != nil {
		return nil, err
	}

	tonic.SetErrorHook(jwt.ErrHook)

	return &RBAC[T]{
		MiddlewareHandler: func(context *gin.Context) {
			errInit := authMiddleware.MiddlewareInit()
			if errInit != nil {
				log.Fatal("authMiddleware.MiddlewareInit() Error:" + errInit.Error())
			}
		},
		AuthMiddleware: authMiddleware,
	}, nil
}
