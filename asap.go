package asap

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	"github.com/satori/go.uuid"
	"strings"
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
	claims.SetJWTID(jit)
	claims.SetIssuedAt(float64(now.Unix()))
	claims.SetExpiration(float64(exp))
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

func asapValidator(kid string, audience string) *jwt.Validator {
	validationFn := func(clientClaims jws.Claims) error {
		if _, p := clientClaims.Issuer(); p == false {
			return errors.New("Missing iss from JWT")
		}
		if _, p := clientClaims.Expiration(); p == false {
			return errors.New("Missing exp from JWT")
		}
		if _, p := clientClaims.IssuedAt(); p == false {
			return errors.New("Missing iat from JWT")
		}
		if _, p := clientClaims.Audience(); p == false {
			return errors.New("Missing aud from JWT")
		}
		if _, p := clientClaims.JWTID(); p == false {
			return errors.New("Missing jti from JWT")
		}

		if issuer, _ := clientClaims.Issuer(); !strings.HasPrefix(kid, issuer+"/") {
			return fmt.Errorf("Issuer %v is not valid for key ID %v", issuer, kid)
		}

		clientAudiences, _ := clientClaims.Audience()
		inAudience := false
		for _, aud := range clientAudiences {
			if strings.Compare(aud, audience) == 0 {
				inAudience = true
				break
			}
		}
		if !inAudience {
			return fmt.Errorf("Missing expected audience %v from JWT", audience)
		}

		issuedAt, _ := clientClaims.IssuedAt()
		expiration, _ := clientClaims.Expiration()

		if time.Unix(int64(issuedAt), 0).Add(time.Hour).Before(time.Unix(int64(expiration), 0)) {
			return fmt.Errorf("iat %v is more than an hour before exp %v", issuedAt, expiration)
		}

		return nil
	}

	return jws.NewValidator(jws.Claims{}, 0, 0, validationFn)
}

func (asap *ASAP) Validate(jwt jwt.JWT, publicKey *rsa.PublicKey) error {
	kid := jwt.(jws.JWS).Protected().Get(KEY_ID).(string) // Eww eww eww
	return jwt.Validate(publicKey, crypto.SigningMethodRS256, asapValidator(kid, asap.ServiceID))
}
