package provider

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/adalundhe/micron/config"
	"github.com/adalundhe/saml-gin"
	"github.com/adalundhe/saml-gin/samlsp"
	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/juju/errors"
)

type SSOOpts struct {
	OverrideMiddleware  samlsp.Middleware
	OverrideKeyPair     *tls.Certificate
	OverrideIDPMetadata *saml.EntityDescriptor
}

type SSOTokenAttrClaims struct {
	Emails    []string `json:"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"`
	FirstName []string `json:"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"`
	LastName  []string `json:"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"`
}

type SSOTokenClaims struct {
	Issuer    string             `json:"iss"`
	Audience  []string           `json:"aud"`
	Expires   int64              `json:"exp"`
	IssuedAt  int64              `json:"iat"`
	NotBefore int64              `json:"nbf"`
	Subject   string             `json:"sub"`
	Attrs     SSOTokenAttrClaims `json:"attr"`
}


type SSOClaimsConstraint interface {
	jwt.Claims
}

type SSOClaimsBuilder[T SSOClaimsConstraint] func(data map[string]interface{}, expiresAt, issuedAt, notBefore time.Time) T


func loadKeyPair(
	config *config.SSOConfig,
) (*tls.Certificate, error) {

	keyPair, err := tls.X509KeyPair([]byte(config.X509PublicKey), []byte(config.X509PrivateKey))
	if err != nil {
		return nil, err
	}

	return &keyPair, nil

}

func NewSSOProvider(
	config *config.SSOConfig,
	apiConfig *config.ApiConfig,
	opts *SSOOpts,
) (SSO, error) {

	var err error
	keyPair := opts.OverrideKeyPair

	if keyPair == nil {
		keyPair, err = loadKeyPair(config)
	}

	if err != nil {
		return nil, err
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, err
	}

	idpMetadataURL, err := url.Parse(config.BaseUrl)
	if err != nil {
		return nil, err
	}

	idpMetadata := opts.OverrideIDPMetadata
	if idpMetadata == nil {
		idpMetadata, err = samlsp.FetchMetadata(
			context.Background(),
			http.DefaultClient,
			*idpMetadataURL,
		)
	}
	if err != nil {
		return nil, err
	}

	ssoUrl, err := url.JoinPath(apiConfig.Url, config.SSOUrlPath)
	if err != nil {
		return nil, err
	}

	rootURL, err := url.Parse(ssoUrl)
	if err != nil {
		return nil, err
	}

	url, err := url.Parse(config.SSORedirectUrl)
	if err != nil {
		return nil, err
	}

	samlSP := opts.OverrideMiddleware
	if samlSP == nil {
		samlSP, err = samlsp.New(samlsp.Options{
			EntityID:         config.EntityId,
			URL:              *rootURL,
			Key:              keyPair.PrivateKey.(*rsa.PrivateKey),
			Certificate:      keyPair.Leaf,
			IDPMetadata:      idpMetadata,
			ForceRedirectUrl: url,
		})
	}

	if err != nil {
		return nil, err
	}

	return &SSOImpl{
		saml:       NewSAMLProvider(samlSP),
		middleware: samlSP.RequireAccount(),
		env:        apiConfig.Env,
		config:     config,
		signingJWKs: []jose.JSONWebKey{
			{
				Key:       keyPair.Leaf.PublicKey.(*rsa.PublicKey),
				Algorithm: string(jose.RS256),
				Use:       "sig",
			},
		},
	}, nil
}

type SSO interface {
	GetMiddlewareHandler() gin.HandlerFunc
	GetACSHandler() func(c *gin.Context) (string, error)
	GetMetadataHandler() interface{}
	GetTokenFromCookie(ctx *gin.Context, jws JWSProvider, authorizator func(ctx *gin.Context, claims *SSOTokenClaims) (string, error)) (string, error)
	Logout(ctx *gin.Context) (*url.URL, error)
}

type SSOImpl struct {
	saml        SAMLProvider
	middleware  gin.HandlerFunc
	env         string
	config      *config.SSOConfig
	signingJWKs []jose.JSONWebKey
}

func (s *SSOImpl) GetMiddlewareHandler() gin.HandlerFunc {
	return s.saml.GetMiddlewareHandler()
}

func (s *SSOImpl) GetACSHandler() func(c *gin.Context) (string, error) {
	return s.saml.GetACSHandler()
}

func (s *SSOImpl) GetMetadataHandler() interface{} {
	return s.saml.GetMetadataHandler()
}

func (s *SSOImpl) GetTokenFromCookie(ctx *gin.Context, jws JWSProvider, authorizator func(ctx *gin.Context, claims *SSOTokenClaims) (string, error)) (string, error) {
	// Here GetTokenFromCookie extracts the SAML token and accepts an "authorizator"
	// function verifySSOTokenFromClaims. This allows us to keep validation upfront
	// with the API, make tweaks without breaking token extraction, etc.

	// On its own, GetTokenFromCookie extracts the JWT from cookie, verifies the
	// signature, and returns the token and/or error.

	// The Authorizator is an arbitrary function accepting a Gin Context and SSOTokenClaims
	// that returns the parsed token (or an empty string) and an error if any. If an error,
	// the validation has failed and we should return the error. Else we should ocntinue and
	// set the token.

	token, err := ctx.Cookie("token")
	if err != nil {
		return "", errors.NewForbidden(err, "No valid token found")
	}

	claims := &SSOTokenClaims{}

	if _, err := ctx.Cookie("jwt"); err == nil {
		http.SetCookie(ctx.Writer, &http.Cookie{
			Name:     "jwt",
			Value:    url.QueryEscape(""),
			Path:     "/",
			Domain:   "",
			Expires:  time.Unix(0, 0),
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
		})
	}

	tokenBytes, err := jws.VerifyFromKeys(token, s.signingJWKs)
	if err != nil {
		return "", err
	}

	if err := json.Unmarshal(tokenBytes, claims); err != nil {
		return "", err
	}

	return authorizator(ctx, claims)

}

func (s *SSOImpl) Logout(ctx *gin.Context) (*url.URL, error) {
	logoutUrl, err := s.saml.Logout(ctx)
	if err != nil {
		return nil, err
	}

	// We directly call http.SetCookie here
	// to clear so we can set Expires.
	http.SetCookie(ctx.Writer, &http.Cookie{
		Name:     "jwt",
		Value:    url.QueryEscape(""),
		Path:     "/",
		Domain:   "",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
	})
	//redirect to the IDP Single log out URLwith the SAMLRequests for logout embedded
	// http.Redirect(w, r, url.String(), http.StatusFound)
	return logoutUrl, nil

}
