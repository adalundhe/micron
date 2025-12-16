package provider

import (
	"net/url"

	"github.com/adalundhe/saml-gin"
	"github.com/adalundhe/saml-gin/samlsp"
	"github.com/gin-gonic/gin"
)

type SAMLProvider interface {
	GetMiddlewareHandler() gin.HandlerFunc
	GetACSHandler() func(c *gin.Context) (string, error)
	GetMetadataHandler() interface{}
	GetSession(ctx *gin.Context) (samlsp.Session, error)
	MakeRedirectLogoutRequest(nameID string, relayState string) (*url.URL, error)
	DeleteSession(ctx *gin.Context) error
	CreateSession(ctx *gin.Context, assertion *saml.Assertion) error
	Logout(ctx *gin.Context) (*url.URL, error)
}

func NewSAMLProvider(samlSp samlsp.Middleware) SAMLProvider {
	return &SAMLProviderImpl{
		samlSp: samlSp,
	}
}

type SAMLProviderImpl struct {
	samlSp samlsp.Middleware
}

func (saml *SAMLProviderImpl) GetMiddlewareHandler() gin.HandlerFunc {
	return saml.samlSp.RequireAccount()
}

func (saml *SAMLProviderImpl) GetACSHandler() func(c *gin.Context) (string, error) {
	return saml.samlSp.ServeACS
}

func (saml *SAMLProviderImpl) GetMetadataHandler() interface{} {
	return saml.samlSp.ServeMetadata
}

func (saml *SAMLProviderImpl) CreateSession(ctx *gin.Context, assertion *saml.Assertion) error {
	return saml.samlSp.GetSession().CreateSession(ctx, assertion)
}

func (saml *SAMLProviderImpl) GetSession(ctx *gin.Context) (samlsp.Session, error) {
	return saml.samlSp.GetSession().GetSession(ctx)
}

func (saml *SAMLProviderImpl) MakeRedirectLogoutRequest(nameID string, relayState string) (*url.URL, error) {
	sp := saml.samlSp.GetServiceProvider()
	return sp.MakeRedirectLogoutRequest(nameID, relayState)
}

func (saml *SAMLProviderImpl) DeleteSession(ctx *gin.Context) error {
	return saml.samlSp.GetSession().DeleteSession(ctx)
}

func (saml *SAMLProviderImpl) Logout(ctx *gin.Context) (*url.URL, error) {
	return saml.samlSp.Logout(ctx)
}
