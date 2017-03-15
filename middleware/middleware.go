package middleware

import (
	"net/http"
	"regexp"

	"bitbucket.org/atlassian/go-asap"
	"bitbucket.org/atlassian/go-asap/keyprovider"

	"github.com/SermoDigital/jose/jws"
	"github.com/Sirupsen/logrus"
	"github.com/deckarep/golang-set"
)

const (
	HeaderAuthorization = "Authorization"
	HeaderKeyID         = "kid"
)

var bearerRegexp = regexp.MustCompile("[Bb]earer ")

type Rule struct {
	Regexp  *regexp.Regexp
	Clients mapset.Set
}

func NewRule(r *regexp.Regexp, clients []string) Rule {
	clientSet := mapset.NewSet()
	for _, c := range clients {
		clientSet.Add(c)
	}
	return Rule{
		Regexp:  r,
		Clients: clientSet,
	}
}

type ASAPMiddleware struct {
	ASAP                *asap.ASAP
	PublicKeyProvider   keyprovider.PublicKeyProvider
	AuthenticationRules []Rule
	Logger              *logrus.Logger
}

func (mw *ASAPMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.Handler) {
	route := r.URL.Path
	if !mw.shouldAuth(route) {
		next.ServeHTTP(w, r)
		return
	}

	authorization := r.Header.Get(HeaderAuthorization)
	if authorization == "" {
		mw.logError("missing authorization header")
		w.WriteHeader(403)
		return
	}

	bearer := bearerRegexp.ReplaceAllString(authorization, "")
	jwt, err := mw.ASAP.Parse([]byte(bearer))
	if err != nil {
		mw.logError(err)
		w.WriteHeader(403)
		return
	}

	issuer, _ := jwt.Claims().Issuer()
	if !mw.clientAllowed(route, issuer) {
		mw.logError("not authorized for route")
		w.WriteHeader(403)
		return
	}

	keyID := jwt.(jws.JWS).Protected().Get(HeaderKeyID).(string) // Eww eww eww
	publicKey, err := mw.PublicKeyProvider.GetPublicKey(keyID)
	if err != nil {
		mw.logError(err)
		w.WriteHeader(403)
		return
	}

	err = mw.ASAP.Validate(jwt, publicKey)
	if err != nil {
		mw.logError(err)
		w.WriteHeader(403)
		return
	}

	next.ServeHTTP(w, r)
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

func (mw *ASAPMiddleware) logError(args ...interface{}) {
	if mw.Logger != nil {
		mw.Logger.Error(args)
	} else {
		logrus.Error(args)
	}
}
