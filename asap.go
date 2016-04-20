package asap

import (
	"bitbucket.org/drpotato_atlassian/go-asap/keyprovider"
	"crypto/rsa"
	"errors"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/satori/go.uuid"
	"time"
)

const KEY_ID = "kid"

type ASAP struct {
	ServiceID          string
	KeyID              string
	AuthorisedSubjects []string
	PublicKeyProvider  keyprovider.PublicKeyProvider
}

func NewASAP(keyIdentifier, serviceID string, authorisedSubjects []string, publicKeyProvider keyprovider.PublicKeyProvider) (asap *ASAP) {
	return &ASAP{
		KeyID:              keyIdentifier,
		ServiceID:          serviceID,
		AuthorisedSubjects: authorisedSubjects,
		PublicKeyProvider:  publicKeyProvider,
	}
}

func (asap *ASAP) Sign(audience string, privateKey *rsa.PrivateKey) (token []byte, err error) {
	if privateKey == nil {
		return nil, errors.New("nil reference to privateKey")
	}
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

	jwt := jws.NewJWT(claims, crypto.SigningMethodRS256)
	return jwt.Serialize(privateKey)
}

func (asap *ASAP) Verify(token []byte) (err error) {
	jwt, err := jws.ParseJWT(token)
	if err != nil {
		return err
	}

	keyID, ok := jwt.Claims().Get(KEY_ID).(string)
	if !ok {
		return errors.New("No identifier in claims")
	}

	publicKey, err := asap.PublicKeyProvider.GetPublicKey(keyID)
	if err != nil {
		return err
	}

	return jwt.Validate(publicKey, crypto.SigningMethodRS256)
}
