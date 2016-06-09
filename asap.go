package asap

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"bitbucket.org/drpotato_atlassian/go-asap/methods"
	"bitbucket.org/drpotato_atlassian/go-asap/validator"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	"github.com/satori/go.uuid"
)

const KEY_ID = "kid"
const ALGORITHM = "alg"

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

func (asap *ASAP) signClaims(claims jws.Claims, privateKey interface{}, signingMethod crypto.SigningMethod) (token []byte, err error) {
	jwt := jws.NewJWT(claims, signingMethod)

	// Need to hack the kid attribute into the right JWS header part, since jose
	// doesn't support adding to that yet.
	jwt.(jws.JWS).Protected().Set(KEY_ID, asap.KeyID)

	return jwt.Serialize(privateKey)
}

func (asap *ASAP) Sign(audience string, privateKey interface{}) (token []byte, err error) {

	var signingMethod crypto.SigningMethod

	switch privateKey.(type) {
	case *rsa.PrivateKey:
		signingMethod = crypto.SigningMethodRS256
	case *ecdsa.PrivateKey:
		signingMethod = crypto.SigningMethodES256
	default:
		return nil, errors.New("bad private key")
	}

	claims := asap.makeClaims(audience)
	return asap.signClaims(claims, privateKey, signingMethod)
}

func (asap *ASAP) Parse(token []byte) (jwt.JWT, error) {
	return jws.ParseJWT(token)
}

func (asap *ASAP) Validate(jwt jwt.JWT, publicKey interface{}) error {
	header := jwt.(jws.JWS).Protected()
	kid := header.Get(KEY_ID).(string)
	alg := header.Get(ALGORITHM).(string)

	signingMethod := methods.SigningMethodMap[alg]
	if signingMethod == nil {
		return errors.New(fmt.Sprintf("Unsupported algorithm: %s", alg))
	}

	return jwt.Validate(publicKey, signingMethod, validator.GenerateValidator(kid, asap.ServiceID))
}
