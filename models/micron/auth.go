package micronapi

type GetSAMLRedirectUrlRequest struct {
	Domain string `query:"domain"`
}

type GetSAMLRedirectUrlResponse struct {
	RedirectUrl string `json:"redirect_url"`
}

type ReceiveSAMLCallbackRequest struct {
	SAMLAccessCode string `query:"saml_access_code"`
}

type ReceiveSAMLCallbackResponse struct {
	Message string `json:"message"`
}
