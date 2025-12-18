package jwtmiddleware

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrTokenExpired = errors.New("token is expired")
	ErrInvalidToken = errors.New("invalid token")
)

type ClaimsConstraint interface {
	jwt.Claims
}

type JWTConfig struct {
	SecretKey        string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL  time.Duration
	AccessCookieName string
	RefreshCookieName string
	CSRFCookieName   string
	Domain           string
	Secure           bool
}

type ClaimsBuilder[T ClaimsConstraint] func(data map[string]interface{}, expiresAt, issuedAt, notBefore time.Time) T
type Verifier[T ClaimsConstraint] func(token jwt.Claims, claims T) (T, error)

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

func GenerateTokens[T ClaimsConstraint](
	config JWTConfig,
	builder ClaimsBuilder[T],
	data map[string]interface{},
) (*TokenPair, error) {
	now := time.Now()
	
	accessClaims := builder(data, now.Add(config.AccessTokenTTL), now, now)
	
	refreshClaims := builder(data, now.Add(config.RefreshTokenTTL), now, now)
	
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString([]byte(config.SecretKey))
	if err != nil {
		return nil, err
	}
	
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(config.SecretKey))
	if err != nil {
		return nil, err
	}
	
	csrfToken, err := generateCSRFToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate CSRF token: %w", err)
	}
	
	return &TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		CSRFToken:    csrfToken,
	}, nil
}

func ValidateToken[T ClaimsConstraint](
	config JWTConfig,
	tokenString string,
	claimsPtr T,
	verifier Verifier[T],
) (T, error) {
	var zero T
	
	token, err := jwt.ParseWithClaims(tokenString, claimsPtr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return []byte(config.SecretKey), nil
	})
	
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return zero, ErrTokenExpired
		}
		return zero, ErrInvalidToken
	}
	
	if claims, err := verifier(token.Claims, claimsPtr); err == nil && token.Valid {
		return claims, nil
	}
	
	return zero, ErrInvalidToken
}

func SetAuthCookies(c *gin.Context, config JWTConfig, tokens *TokenPair) {
	c.SetCookie(
		config.AccessCookieName,
		tokens.AccessToken,
		int(config.AccessTokenTTL.Seconds()),
		"/",
		config.Domain,
		config.Secure,
		true,
	)
	
	c.SetCookie(
		config.RefreshCookieName,
		tokens.RefreshToken,
		int(config.RefreshTokenTTL.Seconds()),
		"/",
		config.Domain,
		config.Secure,
		true,
	)
	
	c.SetCookie(
		config.CSRFCookieName,
		tokens.CSRFToken,
		int(config.AccessTokenTTL.Seconds()),
		"/",
		config.Domain,
		config.Secure,
		false,
	)
}

func ClearAuthCookies(c *gin.Context, config JWTConfig) {
	c.SetCookie(config.AccessCookieName, "", -1, "/", config.Domain, config.Secure, true)
	c.SetCookie(config.RefreshCookieName, "", -1, "/", config.Domain, config.Secure, true)
	c.SetCookie(config.CSRFCookieName, "", -1, "/", config.Domain, config.Secure, false)
}

func GetTokenFromCookie(c *gin.Context, cookieName string) (string, error) {
	token, err := c.Cookie(cookieName)
	if err != nil {
		return "", err
	}
	return token, nil
}

type ClaimsFactory[T ClaimsConstraint] func() T

func JWTAuthMiddleware[T ClaimsConstraint](
	config JWTConfig,
	factory ClaimsFactory[T],
	builder ClaimsBuilder[T],
	verifier Verifier[T],
	extractData func(T) map[string]interface{},
) gin.HandlerFunc {
	return func(c *gin.Context) {
		accessToken, err := GetTokenFromCookie(c, config.AccessCookieName)
		if err != nil {
			c.JSON(401, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}
		
		accessClaims := factory()
		accessClaims, err = ValidateToken(config, accessToken, accessClaims, verifier)
		if err != nil {
			if err == ErrTokenExpired {
				refreshToken, refreshErr := GetTokenFromCookie(c, config.RefreshCookieName)
				if refreshErr != nil {
					c.JSON(401, gin.H{"error": "token expired"})
					c.Abort()
					return
				}
				
				refreshClaims := factory()
				refreshClaims, refreshErr = ValidateToken(config, refreshToken, refreshClaims, verifier)
				if refreshErr != nil {
					c.JSON(401, gin.H{"error": "refresh token invalid"})
					c.Abort()
					return
				}
				
				data := extractData(refreshClaims)
				newTokens, tokenErr := GenerateTokens(config, builder, data)
				if tokenErr != nil {
					c.JSON(500, gin.H{"error": "failed to refresh token"})
					c.Abort()
					return
				}
				
				SetAuthCookies(c, config, newTokens)
				accessClaims = refreshClaims
			} else {
				c.JSON(401, gin.H{"error": "invalid token"})
				c.Abort()
				return
			}
		}
		
		if c.Request.Method != "GET" && c.Request.Method != "HEAD" {
			csrfToken, err := GetTokenFromCookie(c, config.CSRFCookieName)
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
