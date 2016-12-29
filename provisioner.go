package asap

import (
	"os"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	uuid "github.com/satori/go.uuid"
)

// Provisioner is a componenet used to generate new ASAP tokens
// for outgoing requests.
type Provisioner interface {
	Provision() (Token, error)
}

type standardProvisioner struct {
	kid           string
	jitProvider   func() string
	ttl           time.Duration
	issuer        string
	audience      []string
	signingMethod crypto.SigningMethod
}

func (p *standardProvisioner) Provision() (Token, error) {
	var claims = jws.Claims{}
	claims.SetIssuer(p.issuer)
	claims.SetJWTID(p.jitProvider())
	claims.SetIssuedAt(time.Now())
	claims.SetExpiration(time.Now().Add(p.ttl))
	claims.SetAudience(p.audience...)
	var t = jws.NewJWT(claims, p.signingMethod)
	t.(jws.JWS).Protected().Set(ClaimKeyID, p.kid)
	return t, nil
}

func newProvisioner(kid string, ttl time.Duration, issuer string, audience []string, signingMethod crypto.SigningMethod) Provisioner {
	return &standardProvisioner{kid, func() string { return uuid.NewV4().String() }, ttl, issuer, audience, signingMethod}
}

func NewRSProvisioner(kid string, issuer string, audience []string, ttl time.Duration) Provisioner {
	return newProvisioner(kid, ttl, issuer, audience, crypto.SigningMethodRS256)
}

func NewESProvisioner(kid string, issuer string, audience []string, ttl time.Duration) Provisioner {
	return newProvisioner(kid, ttl, issuer, audience, crypto.SigningMethodES256)
}

// NewMicrosProvisioner uses the contracted ASAP env var to populate the
// provisioner. Contract documentation: https://extranet.atlassian.com/pages/viewpage.action?pageId=2763562051
func NewMicrosProvisioner(audience []string, ttl time.Duration) Provisioner {
	return newProvisioner(os.Getenv("ASAP_KEY_ID"), ttl, os.Getenv("ASAP_ISSUER"), audience, crypto.SigningMethodRS256)
}
