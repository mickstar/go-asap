package asap

import (
	"crypto/rsa"
	"errors"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	"github.com/satori/go.uuid"
	"time"
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
	exp := now.Add(time.Minute).Unix()

	claims := jws.Claims{}
	claims.SetIssuer(asap.ServiceID)
	claims.Set(KEY_ID, asap.KeyID)
	claims.SetJWTID(jit)
	claims.SetIssuedAt(float64(now.Unix()))
	claims.SetExpiration(float64(exp))
	claims.SetAudience(audience)

	return claims
}

func signClaims(claims jws.Claims, privateKey *rsa.PrivateKey, signingMethod crypto.SigningMethod) (token []byte, err error) {
	jwt := jws.NewJWT(claims, signingMethod)
	return jwt.Serialize(privateKey)
}

func (asap *ASAP) Sign(audience string, privateKey *rsa.PrivateKey) (token []byte, err error) {
	if privateKey == nil {
		return nil, errors.New("nil reference to privateKey")
	}
	claims := asap.makeClaims(audience)
	return signClaims(claims, privateKey, crypto.SigningMethodRS256)
}

func (asap *ASAP) Parse(token []byte) (jwt jwt.JWT, err error) {
	return jws.ParseJWT(token)
}

func (asap *ASAP) Validate(jwt jwt.JWT, publicKey *rsa.PublicKey) (err error) {
	return jwt.Validate(publicKey, crypto.SigningMethodRS256)
}
