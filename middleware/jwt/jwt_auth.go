package jwtmiddleware

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/adalundhe/micron/config"
	"github.com/adalundhe/micron/internal/provider"
	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	jujuErr "github.com/juju/errors"
)

var (
	ErrTokenExpired = errors.New("token is expired")
	ErrInvalidToken = errors.New("invalid token")
)

type ClaimsConstraint interface {
	jwt.Claims
}

type Parser[T ClaimsConstraint] func(data interface{}) (T, error)
type ClaimsBuilder[T ClaimsConstraint] func(claims T, expiresAt, issuedAt, notBefore time.Time) (T, error)
type Verifier[T ClaimsConstraint] func(ctx *gin.Context, claims T) (T, error)

type JWTMiddleware[T ClaimsConstraint] struct {
	Envs map[string]*config.EnvironmentConfig
	SecretKey        string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL  time.Duration
	AccessCookieName string
	RefreshCookieName string
	CSRFCookieName   string
	Domain           string
	Secure           bool
	TokenLookup 	string
	TokenHeadName	string
	RefreshTokenLookup 	string
	RefreshTokenHeadName	string
	Parse Parser[T]
	Verify Verifier[T]
	Build ClaimsBuilder[T]
	CreateEmpty func() T
	SignerName string
	Algorithm string
	Signer provider.JWSProvider
}


type DefaultClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
	CSRFToken    string
}

func (mw *JWTMiddleware[T]) GenerateTokens(
	access T,
	refresh T,
) (*TokenPair, error) {
	now := time.Now()
	
	accessClaims, err := mw.Build(access, now.Add(mw.AccessTokenTTL), now, now)
	if err != nil {
		return nil, err
	}
	
	refreshClaims, err := mw.Build(refresh, now.Add(mw.RefreshTokenTTL), now, now)
	if err != nil {
		return nil, err
	}

	accessTokenPayload, err := json.Marshal(accessClaims)
	if err != nil {
		return  nil, err
	}

	refreshTokenPayload, err := json.Marshal(refreshClaims)
	if err != nil {
		return  nil, err
	}
	
	
	accessToken, err := mw.Signer.Sign(accessTokenPayload, mw.SignerName)
	if err != nil {
		return nil, err
	}

	refreshToken, err := mw.Signer.Sign(refreshTokenPayload, mw.SignerName)
	if err != nil {
		return nil, err
	}

	
	csrfToken, err := generateCSRFToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate CSRF token: %w", err)
	}
	
	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		CSRFToken:    csrfToken,
	}, nil
}

func (mw *JWTMiddleware[T]) validate(ctx *gin.Context, token string) (T, error) {

	claims := mw.CreateEmpty()

	payload, err := mw.Signer.Verify(token, mw.SignerName, jose.SignatureAlgorithm(mw.Algorithm))
	if err != nil {
		return claims, err
	}

	jwtToken := jwt.New(jwt.GetSigningMethod(mw.Algorithm))
	mapped := jwtToken.Claims.(jwt.MapClaims)


	err = json.Unmarshal(payload, &mapped)
	if err != nil {
		return claims, err
	}
	

	if claims, err := mw.Parse(mapped); err != nil {
		return claims, err
	}

	if claims, err := mw.Verify(ctx, claims); err != nil {
		return claims, err
	}

	return claims, err
}


func (mw *JWTMiddleware[T]) ExtractAndValidateRefreshToken(ctx *gin.Context) (T, error) {
	claims := mw.CreateEmpty()

	refreshToken, err := extractToken(ctx, mw.RefreshTokenHeadName, mw.RefreshTokenHeadName)
	if err != nil {
		return claims, err
	}

	return mw.validate(ctx, refreshToken)


}

func (mw *JWTMiddleware[T]) SetAuthCookies(c *gin.Context, tokens *TokenPair) {
	c.SetCookie(
		mw.AccessCookieName,
		tokens.AccessToken,
		int(mw.AccessTokenTTL.Seconds()),
		"/",
		mw.Domain,
		mw.Secure,
		true,
	)
	
	c.SetCookie(
		mw.RefreshCookieName,
		tokens.RefreshToken,
		int(mw.RefreshTokenTTL.Seconds()),
		"/",
		mw.Domain,
		mw.Secure,
		true,
	)
	
	c.SetCookie(
		mw.CSRFCookieName,
		tokens.CSRFToken,
		int(mw.AccessTokenTTL.Seconds()),
		"/",
		mw.Domain,
		mw.Secure,
		false,
	)
}

func  (mw *JWTMiddleware[T]) ClearAuthCookies(c *gin.Context) {
	c.SetCookie(mw.AccessCookieName, "", -1, "/", mw.Domain, mw.Secure, true)
	c.SetCookie(mw.RefreshCookieName, "", -1, "/", mw.Domain, mw.Secure, true)
	c.SetCookie(mw.CSRFCookieName, "", -1, "/", mw.Domain, mw.Secure, false)
}

func (mw *JWTMiddleware[T]) GetTokenFromCookie(c *gin.Context) (string, error) {
	token, err := c.Cookie(mw.CSRFCookieName)
	if err != nil {
		return "", err
	}
	return token, nil
}

func extractToken(ctx *gin.Context, lookup string, name string) (string, error) {
	methods := strings.Split(lookup, ",")
	var token string
	var err error


	for _, method := range methods {
		if len(token) > 0 {
			break
		}

		parts := strings.Split(strings.TrimSpace(method), ":")
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		switch k {
		case "header":
			token, err = jwtFromHeader(ctx, v, name)
		case "query":
			token, err = jwtFromQuery(ctx, v)
		case "cookie":
			token, err = jwtFromCookie(ctx, v)
		case "param":
			token, err = jwtFromParam(ctx, v)
		case "form":
			token, err = jwtFromForm(ctx, v)
		}
	}

	if err != nil {
		return "", err
	}

	return token, nil
}

func jwtFromHeader(c *gin.Context, key string, name string) (string, error) {
	authHeader := c.Request.Header.Get(key)

	if authHeader == "" {
		return "", jujuErr.Unauthorized
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == name) {
		return "", jujuErr.Unauthorized
	}

	return parts[1], nil
}


func jwtFromQuery(c *gin.Context, key string) (string, error) {
	token := c.Query(key)

	if token == "" {
		return "", jujuErr.Unauthorized
	}

	return token, nil
}

func jwtFromCookie(c *gin.Context, key string) (string, error) {
	cookie, _ := c.Cookie(key)

	if cookie == "" {
		return "", jujuErr.Unauthorized
	}

	return cookie, nil
}

func jwtFromParam(c *gin.Context, key string) (string, error) {
	token := c.Param(key)

	if token == "" {
		return "", jujuErr.Unauthorized
	}

	return token, nil
}

func jwtFromForm(c *gin.Context, key string) (string, error) {
	token := c.PostForm(key)

	if token == "" {
		return "", jujuErr.Unauthorized
	}

	return token, nil
}

type ClaimsFactory[T ClaimsConstraint] func() T

func New[T ClaimsConstraint](
	mw JWTMiddleware[T],
) gin.HandlerFunc {

	jwks, err := provider.NewJWSProviderFromEnvironments(mw.Envs)
	if err != nil {
		log.Fatalf("Could not load signing keys - %s", err.Error())
	}

	mw.Signer = jwks

	return func(c *gin.Context) {
		accessToken, err := extractToken(c, mw.TokenLookup, mw.TokenHeadName)
		if err != nil {
			c.JSON(401, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}


		accessClaims, err := mw.validate(c, accessToken)
		if err != nil {
			if err == ErrTokenExpired {
				refreshToken, refreshErr := extractToken(c, mw.RefreshTokenHeadName, mw.RefreshTokenHeadName)
				if refreshErr != nil {
					c.JSON(401, gin.H{"error": "token expired"})
					c.Abort()
					return
				}
				
				refreshClaims, refreshErr := mw.validate(c, refreshToken)
				if refreshErr != nil {
					c.JSON(401, gin.H{"error": "refresh token invalid"})
					c.Abort()
					return
				}
				
				newTokens, tokenErr := mw.GenerateTokens(accessClaims, refreshClaims)
				if tokenErr != nil {
					c.JSON(500, gin.H{"error": "failed to refresh token"})
					c.Abort()
					return
				}
				
				mw.SetAuthCookies(c, newTokens)
				accessClaims = refreshClaims
			} else {
				c.JSON(401, gin.H{"error": "invalid token"})
				c.Abort()
				return
			}
		}
		
		if c.Request.Method != "GET" && c.Request.Method != "HEAD" {
			csrfToken, err := mw.GetTokenFromCookie(c)
			if err != nil {
				c.JSON(403, gin.H{"error": "csrf token missing"})
				c.Abort()
				return
			}
			
			headerCSRF := c.GetHeader("X-CSRF-Token")
			if headerCSRF != "" && headerCSRF != csrfToken {
				c.JSON(403, gin.H{"error": "csrf token mismatch"})
				c.Abort()
				return
			}
		}
		
		c.Set("claims", accessClaims)
		
		c.Next()
	}
}

func generateCSRFToken() (string, error) {
	const tokenLength = 64
	
	bytes := make([]byte, tokenLength)
	
	n, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("crypto/rand failed: %w", err)
	}
	
	if n != tokenLength {
		return "", fmt.Errorf("incomplete random read: got %d bytes, expected %d", n, tokenLength)
	}
	
	token := base64.RawURLEncoding.EncodeToString(bytes)
	
	return token, nil
}
