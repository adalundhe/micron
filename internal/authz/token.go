package authz

import (
	"errors"
	"log/slog"

	"github.com/golang-jwt/jwt/v4"
)

type Actor struct {
	ClientId string `json:"client_id"`
}

type AuthClaims struct {
	Issuer     string `json:"issuer"`
	Subject    string `json:"sub"`
	ClientId   string `json:"client_id"`
	Audience   string `json:"aud"`
	MayAct     Actor  `json:"may_act"`
	Expires    int64  `json:"exp"`
	Originated int64  `json:"orig_iat"`
	NotBefore  int64  `json:"nbf"`
}

func MapToAuthClaims(claims interface{}) (*AuthClaims, error) {
	if v, ok := claims.(jwt.MapClaims); ok {
		return MapJwtMapToAuthClaims(v)
	}

	return nil, errors.New("could not parse claims")
}

func MapJwtMapToAuthClaims(claims jwt.MapClaims) (*AuthClaims, error) {
	iss, ok := claims["issuer"].(string)
	if !ok {
		slog.Debug("Err. - could not map issuer")
		return nil, errors.New("could not map issuer")
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		slog.Debug("Could not map subject")
		return nil, errors.New("could not map subject")
	}

	client_id, ok := claims["client_id"].(string)
	if !ok {
		slog.Debug("Could not map client id")
		return nil, errors.New("could not map client id")
	}

	aud, ok := claims["aud"].(string)
	if !ok {
		slog.Debug("Could not map audience")
		return nil, errors.New("could not map audience")
	}

	may_act, ok := claims["may_act"].(map[string]interface{})
	if !ok {
		slog.Debug("Could not map actor")
		return nil, errors.New("could not map actor")
	}

	actor_id, ok := may_act["client_id"].(string)
	if !ok {
		slog.Debug("Could not map actor client id")
		return nil, errors.New("could not map actor client id")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		slog.Debug("Could not map expiry")
		return nil, errors.New("could not map expiry")
	}

	orig_iat, ok := claims["orig_iat"].(float64)
	if !ok {
		slog.Debug("Could not map origination time")
		return nil, errors.New("could not map origination time")
	}

	nbf, ok := claims["nbf"].(float64)
	if !ok {
		slog.Debug("Could not map not before time")
		return nil, errors.New("could not map not before time")
	}

	return &AuthClaims{
		Issuer:   iss,
		Subject:  sub,
		ClientId: client_id,
		Audience: aud,
		MayAct: Actor{
			ClientId: actor_id,
		},
		Expires:    int64(exp),
		Originated: int64(orig_iat),
		NotBefore:  int64(nbf),
	}, nil
}
