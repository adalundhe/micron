package provider

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/adalundhe/micron/config"
	"github.com/go-jose/go-jose/v4"
)

type GitHubOIDCOptions struct {
	ActionRequestUrl   string `json:"action_request_url"`
	ActionRequestToken string `json:"action_request_token"`
	Audience           string `json:"audience"`
}

type GitHubOIDCToken struct {
	Value string `json:"value"`
}

type WellKNownKeys struct {
	RawKeys []json.RawMessage `json:"keys"`
}

type JWSProvider interface {
	Sign(payload []byte, signerName string) (string, error)
	ExtractUnverifiedPayload(token string, signingMethods ...jose.SignatureAlgorithm) ([]byte, error)
	SignWellKnown(payload []byte, knownProvider string) (string, error)
	VerifyFromKeys(token string, verifiers []jose.JSONWebKey) ([]byte, error)
	Verify(token string, verifierName string, signingMethods ...jose.SignatureAlgorithm) ([]byte, error)
	VerifyWellKnown(token string, providerName string, signingMethods ...jose.SignatureAlgorithm) ([]byte, error)
}

func NewJWSProviderFromEnvironments(cfg map[string]*config.EnvironmentConfig, clients ...http.Client) (JWSProvider, error) {
	signers := make(map[string]jose.Signer)
	verifierKeys := make(map[string]interface{})
	wellKnownUrls := make(map[string]string, 0)

	for envName, envCfg := range cfg {

		for knownProvider, knownUrl := range envCfg.WellKnownUrls {
			wellKnownUrls[knownProvider] = knownUrl
		}

		if len(envCfg.Jwks) == 0 {
			continue
		}

		for _, jwk := range envCfg.Jwks {
			key := &jose.JSONWebKey{}
			err := key.UnmarshalJSON([]byte(jwk))
			if err != nil {
				return nil, err
			}
			if key.IsPublic() {
				if _, ok := verifierKeys[envName]; ok {
					return nil, fmt.Errorf("multiple public keys for environment %s", envName)
				}
				verifierKeys[envName] = key
			} else {
				if _, ok := signers[envName]; ok {
					return nil, fmt.Errorf("multiple private keys for environment %s", envName)
				}
				signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(key.Algorithm), Key: key.Key}, nil)
				if err != nil {
					return nil, err
				}
				signers[envName] = signer
			}
		}
	}

	client := http.DefaultClient
	if len(clients) > 0 {
		client = &clients[0]
	}

	wellKnownSigners := make(map[string][]jose.Signer, 0)
	wellKnownVerifierKeys := make(map[string][]jose.JSONWebKey, 0)

	return &JWSProviderImpl{
		Client:                client,
		Signers:               signers,
		VerifierKeys:          verifierKeys,
		WellKnownUrls:         wellKnownUrls,
		WellKnownSigners:      wellKnownSigners,
		WellKnownVerifierKeys: wellKnownVerifierKeys,
	}, nil
}

type JWSProviderImpl struct {
	Client  *http.Client
	Signers map[string]jose.Signer
	// this should be a map of verifier names to verifier keys
	// see https://github.com/go-jose/go-jose/blob/fdc2ceb0bbe2a29c582edfe07ea914c8dacd7e1b/signing.go#L178-L205 for supported key types
	VerifierKeys          map[string]interface{}
	WellKnownUrls         map[string]string
	WellKnownSigners      map[string][]jose.Signer
	WellKnownVerifierKeys map[string][]jose.JSONWebKey
}

func (s *JWSProviderImpl) Sign(payload []byte, signerName string) (string, error) {
	if payload == nil {
		return "", fmt.Errorf("payload is nil")
	}
	signer, ok := s.Signers[signerName]
	if !ok {
		return "", fmt.Errorf("signer %s not found", signerName)
	}
	signedPayload, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	serializedPayload, err := signedPayload.CompactSerialize()
	if err != nil {
		return "", err
	}
	return serializedPayload, nil
}

func (s *JWSProviderImpl) ExtractUnverifiedPayload(token string, signingMethods ...jose.SignatureAlgorithm) ([]byte, error) {
	signatureAlgorithm := jose.RS512
	if len(signingMethods) > 0 {
		signatureAlgorithm = signingMethods[0]
	}

	verifiedToken, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{signatureAlgorithm})
	if err != nil {
		return nil, err
	}
	payload := verifiedToken.UnsafePayloadWithoutVerification()
	return payload, nil
}

func (s *JWSProviderImpl) SignWellKnown(payload []byte, knownProvider string) (string, error) {
	if payload == nil {
		return "", fmt.Errorf("payload is nil")
	}

	url, ok := s.WellKnownUrls[knownProvider]
	if !ok {
		return "", fmt.Errorf("%s is not a configured well known JWT/JWK provider", knownProvider)
	}

	var err error
	if _, ok := s.WellKnownSigners[knownProvider]; !ok {
		err = s.loadWellKnownKeys(url, knownProvider)
	}

	if err != nil {
		return "", err
	}

	return s.signWithWellKnownJWK(knownProvider, payload)

}

func (s *JWSProviderImpl) VerifyFromKeys(token string, verifiers []jose.JSONWebKey) ([]byte, error) {
	var err error

	for _, verifier := range verifiers {

		signatureAlgorithm := jose.SignatureAlgorithm(verifier.Algorithm)
		verifiedToken, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{signatureAlgorithm})
		if err != nil {
			return nil, err
		}

		payload, err := verifiedToken.Verify(verifier)
		if err == nil {

			return payload, nil
		}

		slog.Info("jwt verification failed: %w", slog.Any("err", err))

	}

	return nil, err

}

func (s *JWSProviderImpl) VerifyWellKnown(token string, knownProvider string, signingMethods ...jose.SignatureAlgorithm) ([]byte, error) {

	url, ok := s.WellKnownUrls[knownProvider]
	if !ok {
		return nil, fmt.Errorf("%s is not a configured well known JWT/JWK provider", knownProvider)
	}

	var err error
	if _, ok := s.WellKnownVerifierKeys[knownProvider]; !ok {
		err = s.loadWellKnownKeys(url, knownProvider)
	}

	if err != nil {
		return nil, err
	}

	return s.verifyWithWellKnownJWK(token, knownProvider, signingMethods...)
}

func (s *JWSProviderImpl) Verify(token string, verifierName string, signingMethods ...jose.SignatureAlgorithm) ([]byte, error) {
	signatureAlgorithm := jose.RS512
	if len(signingMethods) > 0 {
		signatureAlgorithm = signingMethods[0]
	}

	verifiedToken, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{signatureAlgorithm})
	if err != nil {
		return nil, err
	}
	verifier, ok := s.VerifierKeys[verifierName]
	if !ok {
		return nil, fmt.Errorf("verifier %s not found", verifierName)
	}
	payload, err := verifiedToken.Verify(verifier)
	if err != nil {
		return nil, fmt.Errorf("jwt verification failed: %w", err)
	}
	return payload, nil
}

func (s *JWSProviderImpl) loadWellKnownKeys(url string, knownProvider string) error {
	wellKnownKeys, err := s.getWellKnownKeys(url)
	if err != nil {
		return err
	}

	if err := s.storeWellKnownKeys(wellKnownKeys, knownProvider); err != nil {
		return err
	}

	return nil
}

func (s *JWSProviderImpl) signWithWellKnownJWK(knownProvider string, payload []byte) (string, error) {

	signers, ok := s.WellKnownSigners[knownProvider]
	if !ok {
		return "", fmt.Errorf("no signers for well known JWT/JWK provider %s", knownProvider)

	}

	var signedPayload *jose.JSONWebSignature
	var err error
	for _, signer := range signers {
		signedPayload, err = signer.Sign(payload)
		if err == nil {
			break
		}
	}

	if err != nil {
		return "", err
	}

	serializedPayload, err := signedPayload.CompactSerialize()
	if err != nil {
		return "", nil
	}

	return serializedPayload, nil
}

func (s *JWSProviderImpl) verifyWithWellKnownJWK(
	token string,
	knownProvider string,
	signingMethods ...jose.SignatureAlgorithm,
) ([]byte, error) {

	verifiers, ok := s.WellKnownVerifierKeys[knownProvider]
	if !ok {
		return nil, fmt.Errorf("no verifiers for well known JWT/JWK provider %s", knownProvider)
	}

	var err error
	for _, verifier := range verifiers {

		signatureAlgorithm := jose.SignatureAlgorithm(verifier.Algorithm)
		if len(signingMethods) > 0 {
			signatureAlgorithm = signingMethods[0]
		}

		verifiedToken, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{signatureAlgorithm})
		if err != nil {
			return nil, err
		}

		payload, err := verifiedToken.Verify(verifier)
		if err == nil {

			return payload, nil
		}

		slog.Info("jwt verification failed: %w", slog.Any("err", err))

	}

	return nil, err
}

func (s *JWSProviderImpl) getWellKnownKeys(url string) (*WellKNownKeys, error) {
	jwksResp, err := s.Client.Get(url)
	if err != nil {
		return nil, err
	}

	defer jwksResp.Body.Close()

	bodyBytes, err := io.ReadAll(jwksResp.Body)
	if err != nil {
		return nil, err
	}

	if jwksResp.StatusCode < 200 || jwksResp.StatusCode >= 300 {
		return nil, fmt.Errorf(
			"request to - %s - failed due to - %s - with error code - %d",
			url,
			string(bodyBytes),
			jwksResp.StatusCode,
		)
	}

	keys := &WellKNownKeys{}

	if err := json.Unmarshal(bodyBytes, keys); err != nil {
		return nil, err
	}

	return keys, err
}

func (s *JWSProviderImpl) storeWellKnownKeys(wellKnownKeys *WellKNownKeys, knownProvider string) error {
	// I'm uncertain how to handle that some
	// providers have multiple keys.
	for _, rawKey := range wellKnownKeys.RawKeys {
		key := jose.JSONWebKey{}
		if err := key.UnmarshalJSON(rawKey); err != nil {
			return err
		}

		if key.IsPublic() {
			s.WellKnownVerifierKeys[knownProvider] = append(s.WellKnownVerifierKeys[knownProvider], key)

		} else {
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(key.Algorithm), Key: key.Key}, nil)
			if err != nil {
				return err
			}

			s.WellKnownSigners[knownProvider] = append(s.WellKnownSigners[knownProvider], signer)
		}
	}

	return nil
}
