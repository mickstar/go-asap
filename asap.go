package asap

import (
	"crypto/rsa"
	"errors"
	"time"

	"bitbucket.org/drpotato_atlassian/go-asap/validator"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	"github.com/satori/go.uuid"
)

const KEY_ID = "kid"

type ASAP struct {
	ServiceID          string
	KeyID              string
	AuthorisedSubjects []string
}

func NewASAP(keyIdentifier, serviceID string, authorisedSubjects []string) *ASAP {
	return &ASAP{
		KeyID:              keyIdentifier,
		ServiceID:          serviceID,
		AuthorisedSubjects: authorisedSubjects,
	}
}

func (asap *ASAP) makeClaims(audience string) jws.Claims {
	now := time.Now()
	jit := uuid.NewV4().String()
	exp := now.Add(time.Minute)

	claims := jws.Claims{}
	claims.SetIssuer(asap.ServiceID)
	claims.SetJWTID(jit)
	claims.SetIssuedAt(now)
	claims.SetExpiration(exp)
	claims.SetAudience(audience)

	return claims
}

func (asap *ASAP) signClaims(claims jws.Claims, privateKey *rsa.PrivateKey, signingMethod crypto.SigningMethod) (token []byte, err error) {
	jwt := jws.NewJWT(claims, signingMethod)

	// Need to hack the kid attribute into the right JWS header part, since jose
	// doesn't support adding to that yet.
	jwt.(jws.JWS).Protected().Set(KEY_ID, asap.KeyID)

	return jwt.Serialize(privateKey)
}

func (asap *ASAP) Sign(audience string, privateKey *rsa.PrivateKey) (token []byte, err error) {
	if privateKey == nil {
		return nil, errors.New("nil reference to privateKey")
	}
	claims := asap.makeClaims(audience)
	return asap.signClaims(claims, privateKey, crypto.SigningMethodRS256)
}

func (asap *ASAP) Parse(token []byte) (jwt.JWT, error) {
	return jws.ParseJWT(token)
}

func (asap *ASAP) Validate(jwt jwt.JWT, publicKey *rsa.PublicKey) error {
	kid := jwt.(jws.JWS).Protected().Get(KEY_ID).(string) // Eww eww eww
	return jwt.Validate(publicKey, crypto.SigningMethodRS256, validator.GenerateValidator(kid, asap.ServiceID))
}
