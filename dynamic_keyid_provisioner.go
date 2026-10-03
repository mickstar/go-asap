package asap

import (
	"time"

	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type DynamicKeyIDProvisioner struct {
	jitProvider   func() string
	ttl           time.Duration
	issuer        string
	audience      []string
	signingMethod SigningMethod
	provider      AutorotatingKeypairProvider
}

func NewDynamicKeyIDProvisioner(ttl time.Duration, issuer string, audience []string, signingMethod SigningMethod, provider AutorotatingKeypairProvider) Provisioner {
	return &DynamicKeyIDProvisioner{func() string { return uuid.New().String() }, ttl, issuer, audience, signingMethod, provider}
}

func (p *DynamicKeyIDProvisioner) Provision() (Token, error) {
	now := nowFunc()
	claims := Claims{}
	claims.SetIssuer(p.issuer)
	claims.SetJWTID(p.jitProvider())
	claims.SetIssuedAt(now)
	claims.SetExpiration(now.Add(p.ttl))
	claims.SetAudience(p.audience...)

	parsed := golangjwt.NewWithClaims(p.signingMethod.m, claims)
	keyID, err := p.provider.GetKeyID()
	if err != nil {
		return nil, err
	}
	parsed.Header[ClaimKeyID] = keyID
	return &token{parsed, claims}, nil
}
