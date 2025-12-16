package auth

import (
	"context"
	"log"
	"log/slog"
	"strings"
	"time"

	adaJwt "github.com/adalundhe/gin-jwt-tonic"
	"github.com/adalundhe/micron/internal/authz"
	"github.com/adalundhe/micron/internal/config"
	"github.com/adalundhe/micron/internal/provider/idp"
	"github.com/adalundhe/micron/internal/stores"
	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
	"github.com/uptrace/bun"
)


var (
	sub       = "sub"
	realm     = "micron"
	client_id = "client_id"
	issuer    = "issuer"
	aud       = "aud"
	// scope     = "scope"
	may_act = "may_act"

	DB                *bun.DB
	Enforcer          *casbin.Enforcer
	Idp               idp.IdentityProvider
	authorizedActors  []string
	authorizedClients []string
	authorizedIssuers []string
)

type TokenAuthOpts struct {
	Validator func(data interface{}, c *gin.Context) bool
	SigningAlgorithm string
	IdentityKey string
	Realm string
	Timeout time.Duration
	MaxRefresh time.Duration
	TokenLookup string
	TokenHeadName string
}

func ContainsValidValue(authorized []string, candidate string) bool {
	for _, value := range authorized {
		if value == candidate {
			return true
		}
	}

	return false
}


func CreateJWTTokenHandler(
	ctx context.Context,
	cfg *config.Config,
	opts TokenAuthOpts,
) (*adaJwt.GinJWTMiddleware[*authz.AuthClaims], error) {

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

	if cfg.Api.Auth != nil && len(cfg.Api.Auth.AllowedActors) > 0 {
		authorizedActors = cfg.Api.Auth.AllowedActors
	}

	if cfg.Api.Auth != nil && len(cfg.Api.Auth.AllowedClients) > 0 {
		authorizedClients = cfg.Api.Auth.AllowedClients
	}

	if cfg.Api.Auth != nil && len(cfg.Api.Auth.AllowedIssuers) > 0 {
		authorizedIssuers = cfg.Api.Auth.AllowedIssuers
	}

	middlewareConfig := &adaJwt.GinJWTMiddleware[*authz.AuthClaims]{
		CheckAllSigners:  true,
		Realm:            realm,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour,
		IdentityKey:      sub,
		SigningAlgorithm: "RS512",
		Validator: func(data interface{}, c *gin.Context) bool {

			var vals *authz.AuthClaims
			var err error
			var ok bool = false

			if vals, err = authz.MapToAuthClaims(data); err != nil {
				slog.Error("Could not map to claims", slog.Any("error", err))
				return false
			}

			userEmail := vals.Subject

			userRepo := stores.NewDbUserRepository(DB)
			user, err := userRepo.GetUserByEmail(ctx, userEmail)
			if err != nil {
				slog.Error("encountered error authenticating identity", slog.Any("error", err))
				return false
			}

			c.Set("user", user)

			if !ContainsValidValue(authorizedActors, vals.MayAct.ClientId) {
				slog.Error("Actor missing from claims or is not valid", slog.Any(may_act, vals.MayAct.ClientId))
				return false
			}

			if !ContainsValidValue(authorizedClients, vals.ClientId) {
				slog.Error("Client missing from claims or is not valid", slog.Any(client_id, vals.ClientId))
				return false
			}

			if !ContainsValidValue(authorizedIssuers, vals.Issuer) {
				slog.Error("Issuer missing from claims or is not valid", slog.Any(issuer, vals.Issuer))
				return false
			}

			if vals.Audience != "api" {
				slog.Error("Audience is missing from claims or is not valid", slog.Any(aud, vals.Audience))
				return false
			}

			nbfMintime := time.Unix(vals.NotBefore, 0).Add(time.Second * 60 * -1).Unix()
			if nbfMintime > time.Now().Unix() {
				slog.Error("Token received too early", slog.Any("nbf", vals.NotBefore))
				return false
			}

			requestPath := c.Request.URL.Path
			requestMethod := c.Request.Method

			Enforcer.LoadPolicy()

			slog.Debug(
				"Enforcer.Enforce parameters",
				slog.String("user", userEmail),
				slog.String("path", requestPath),
				slog.String("method", requestMethod),
			)

			ok, err = Enforcer.Enforce(
				userEmail,
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
				groups, err := Enforcer.GetRolesForUser(userEmail)
				if err != nil {
					slog.Error("Failed to get user groups", slog.Any("error", err))
				}
				slog.Warn(
					"User is not allowed to access api endpoint",
					slog.String("user", userEmail),
					slog.String("groups", strings.Join(groups, ",")),
					slog.String("route", requestPath),
					slog.String("method", requestMethod),
				)

				return ok
			}

			slog.Info(
				"User is allowed to to hit api",
				slog.String("user", userEmail),
				slog.String("route", requestPath),
				slog.String("method", requestMethod),
			)

			return ok
		},
		TokenLookup:   "header: Authorization, query: token, cookie: jwt",
		TokenHeadName: "Bearer",
		TimeFunc:      time.Now,
	}

	if opts.Validator != nil {
		middlewareConfig.Validator = opts.Validator
	}

	if opts.SigningAlgorithm != "" {
		middlewareConfig.SigningAlgorithm = opts.SigningAlgorithm
	}

	if opts.IdentityKey != "" {
		middlewareConfig.IdentityKey = opts.IdentityKey
	}

	if opts.MaxRefresh != 0 {
		middlewareConfig.MaxRefresh = opts.MaxRefresh
	}

	if opts.Realm != "" {
		middlewareConfig.Realm = opts.Realm
	}

	if opts.Timeout != 0 {
		middlewareConfig.Timeout = opts.Timeout
	}

	if opts.TokenHeadName != "" {
		middlewareConfig.TokenHeadName = opts.TokenHeadName
	}

	if opts.TokenLookup != "" {
		middlewareConfig.TokenLookup = opts.TokenLookup
	}

	jwtMiddleware, err := adaJwt.New(middlewareConfig, signers...)

	if err != nil {
		log.Fatalf("failed to create JWT middleware - %s", err)
	}

	return jwtMiddleware, nil
}
