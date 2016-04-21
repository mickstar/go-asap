package middleware

import (
	"bitbucket.org/drpotato_atlassian/go-asap"
	"bitbucket.org/drpotato_atlassian/go-asap/keyprovider"
	"github.com/SermoDigital/jose/jws"
	"github.com/Sirupsen/logrus"
	"github.com/deckarep/golang-set"
	"net/http"
	"regexp"
)

var REGEXP = regexp.MustCompile("[Bb]earer ")

const (
	HEADER_AUTHORIZATION = "Authorization"
	HEADER_KEY_ID        = "kid"
)

type Rule struct {
	Regexp  *regexp.Regexp
	Clients mapset.Set
}

type ASAPMiddleware struct {
	ASAP                *asap.ASAP
	PublicKeyProvider   keyprovider.PublicKeyProvider
	AuthenticationRules []Rule
}

func (mw *ASAPMiddleware) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	route := r.URL.Path
	if !mw.shouldAuth(route) {
		next(rw, r)
		return
	}

	authorization := r.Header.Get(HEADER_AUTHORIZATION)
	if authorization == "" {
		logrus.Error("missing authorization header")
		rw.WriteHeader(403)
		return
	}

	bearer := REGEXP.ReplaceAllString(authorization, "")
	jwt, err := mw.ASAP.Parse([]byte(bearer))
	if err != nil {
		logrus.Error(err)
		rw.WriteHeader(403)
		return
	}

	issuer, _ := jwt.Claims().Issuer()
	if !mw.clientAllowed(route, issuer) {
		logrus.Error("not authorized for route")
		rw.WriteHeader(403)
		return
	}

	keyID := jwt.(jws.JWS).Protected().Get(HEADER_KEY_ID).(string) // Eww eww eww
	publicKey, err := mw.PublicKeyProvider.GetPublicKey(keyID)
	if err != nil {
		logrus.Error(err)
		rw.WriteHeader(403)
		return
	}

	err = mw.ASAP.Validate(jwt, publicKey)
	if err != nil {
		logrus.Error(err)
		rw.WriteHeader(403)
		return
	}

	next(rw, r)
}

func (mw *ASAPMiddleware) shouldAuth(route string) bool {
	for _, r := range mw.AuthenticationRules {
		if r.Regexp.MatchString(route) {
			return true
		}
	}
	return false
}

func (mw *ASAPMiddleware) clientAllowed(route, client string) bool {
	for _, r := range mw.AuthenticationRules {
		if r.Regexp.MatchString(route) {
			return r.Clients.Cardinality() == 0 || r.Clients.Contains(client)
		}
	}
	return false
}
