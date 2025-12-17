package auth

import (
	"context"
	"log"
	"log/slog"
	"strings"
	"time"

	adaJwt "github.com/adalundhe/gin-jwt-tonic"
	"github.com/adalundhe/micron/internal/config"
	"github.com/adalundhe/micron/internal/provider/idp"
	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
	"github.com/uptrace/bun"
)


var (
	DB                *bun.DB
	Enforcer          *casbin.Enforcer
	Idp               idp.IdentityProvider
)

type TokenAuth[T interface{}] struct {
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

func ContainsValidValue(authorized []string, candidate string) bool {
	for _, value := range authorized {
		if value == candidate {
			return true
		}
	}

	return false
}


func (t *TokenAuth[T]) CreateHandler(
	ctx context.Context,
	cfg *config.Config,
) (*adaJwt.GinJWTMiddleware[T], error) {

	var signers []adaJwt.Signer

	for envName, envCfg := range cfg.DeployEnvs {

		keys := []adaJwt.Key{}

		for _, jwk := range envCfg.Jwks {

			keys = append(keys, adaJwt.Key{
				Data:  jwk,
				IsJWK: true,
			})

		}

		signers = append(signers, adaJwt.Signer{
			Name: envName,
			Keys: keys,
		})

	}

	middlewareConfig := &adaJwt.GinJWTMiddleware[T]{
		CheckAllSigners:  true,
		Realm:            t.Realm,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour,
		IdentityKey:      t.IdentifierKey,
		SigningAlgorithm: t.SigningAlgorithm,
		Validator: func(data interface{}, c *gin.Context) bool {

			var vals T
			var err error
			var ok bool = false

			if vals, err = t.MapToClaims(data); err != nil {
				slog.Error("Could not map to claims", slog.Any("error", err))
				return false
			}

			identifier, err := t.Authorize(vals, t.Allowed)
			if err != nil {
				slog.Error("User not authorized:", slog.Any("error", err))
				return false
			}

			requestPath := c.Request.URL.Path
			requestMethod := c.Request.Method

			Enforcer.LoadPolicy()

			ok, err = Enforcer.Enforce(
				identifier,
				requestPath,
				requestMethod,
			)

			slog.Debug(
				"Enforcer.Enforce result",
				slog.Bool("allowed", ok),
				slog.Any("error", err),
			)

			if err != nil {
				slog.Error("Error enforcing policy", slog.Any("error", err))
				return ok
			}

			if !ok {
				groups, err := Enforcer.GetRolesForUser(identifier)
				if err != nil {
					slog.Error("Failed to get user groups", slog.Any("error", err))
				}
				slog.Warn(
					"User is not allowed to access api endpoint",
					slog.String("user", identifier),
					slog.String("groups", strings.Join(groups, ",")),
					slog.String("route", requestPath),
					slog.String("method", requestMethod),
				)

				return ok
			}

			slog.Info(
				"User is allowed to to hit api",
				slog.String("user", identifier),
				slog.String("route", requestPath),
				slog.String("method", requestMethod),
			)

			return ok
		},
		TokenLookup:   "header: Authorization, query: token, cookie: jwt",
		TokenHeadName: "Bearer",
		TimeFunc:      time.Now,
	}

	if t.Validator != nil {
		middlewareConfig.Validator = t.Validator
	}

	if t.SigningAlgorithm != "" {
		middlewareConfig.SigningAlgorithm = t.SigningAlgorithm
	}

	if t.IdentityKey != "" {
		middlewareConfig.IdentityKey = t.IdentityKey
	}

	if t.MaxRefresh != 0 {
		middlewareConfig.MaxRefresh = t.MaxRefresh
	}

	if t.Realm != "" {
		middlewareConfig.Realm = t.Realm
	}

	if t.Timeout != 0 {
		middlewareConfig.Timeout = t.Timeout
	}

	if t.TokenHeadName != "" {
		middlewareConfig.TokenHeadName = t.TokenHeadName
	}

	if t.TokenLookup != "" {
		middlewareConfig.TokenLookup = t.TokenLookup
	}

	jwtMiddleware, err := adaJwt.New(middlewareConfig, signers...)

	if err != nil {
		log.Fatalf("failed to create JWT middleware - %s", err)
	}

	return jwtMiddleware, nil
}
