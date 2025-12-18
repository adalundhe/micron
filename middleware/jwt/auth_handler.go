package jwtmiddleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/juju/errors"
)

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Message string `json:"message"`
	UserID  string `json:"user_id"`
	Username string `json:"username"`
}

type GenericAuthHandler[T ClaimsConstraint] struct {
	config     JWTConfig
	userStore  UserStore
	builder    ClaimsBuilder[T]
	extractData func(T) map[string]interface{}
	verify Verifier[T]
}

type UserStore interface {
	ValidateUser(username, password string) (userID string, err error)
}

func NewGenericAuthHandler[T ClaimsConstraint](
	config JWTConfig,
	userStore UserStore,
	builder ClaimsBuilder[T],
	extractData func(T) map[string]interface{},
) *GenericAuthHandler[T] {
	return &GenericAuthHandler[T]{
		config:     config,
		userStore:  userStore,
		builder:    builder,
		extractData: extractData,
	}
}

func (h *GenericAuthHandler[T]) Login(c *gin.Context, req *LoginRequest) (*LoginResponse, error) {
	userID, err := h.userStore.ValidateUser(req.Username, req.Password)
	if err != nil {
		return nil, errors.NewUnauthorized(err, "Unauthorized request")
	}
	
	data := map[string]interface{}{
		"user_id":  userID,
		"username": req.Username,
	}
	
	tokens, err := GenerateTokens(h.config, h.builder, data)
	if err != nil {
		return nil, err
	}
	
	SetAuthCookies(c, h.config, tokens)
	
	return &LoginResponse{
		Message:  "login successful",
		UserID:   userID,
		Username: req.Username,
	}, nil
}

func (h *GenericAuthHandler[T]) Refresh(c *gin.Context) (string, error) {
	refreshToken, err := GetTokenFromCookie(c, h.config.RefreshCookieName)
	if err != nil {
		return "", errors.NewUnauthorized(err, "Unauthorized request")
	}
	
	var claims T
	claims, err = ValidateToken(c, h.config, refreshToken, claims, h.verify)
	if err != nil {
		return "", errors.NewUnauthorized(err, "Unauthorized request")
	}
	
	data := h.extractData(claims)
	
	newTokens, err := GenerateTokens(h.config, h.builder, data)
	if err != nil {
		return "", err
	}
	
	SetAuthCookies(c, h.config, newTokens)

	return "OK", nil
}

func (h *GenericAuthHandler[T]) GetOwnClaims(c *gin.Context) (*T, error) {
	claimsInterface, exists := c.Get("claims")
	if !exists {
		return nil, errors.NewUnauthorized(errors.New("Encountered an error"), "Unauthorized request")
	}
	
	claims, ok := claimsInterface.(T)
	if !ok {
		return nil, errors.NewUnauthorized(errors.New("Encountered an error"), "Unauthorized request")
	}
	
	return  &claims, nil
}


func (h *GenericAuthHandler[T]) Logout(c *gin.Context) {
	ClearAuthCookies(c, h.config)
	c.JSON(http.StatusOK, gin.H{"message": "logout successful"})
}
