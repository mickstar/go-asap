package asap

import (
	"bitbucket.org/atlassian/go-asap/keyprovider"
	"github.com/SermoDigital/jose/jws"
	"github.com/deckarep/golang-set"
	"log"
	"net/http"
	"regexp"
	"errors"
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

type Middleware struct {
	Handler             http.Handler
	ASAP                *ASAP
	PublicKeyProvider   keyprovider.PublicKeyProvider
	AuthenticationRules []Rule
	Logger              func(v ...interface{})
}

type MiddlewareConfigs struct {
	ASAP                *ASAP
	PublicKeyProvider   keyprovider.PublicKeyProvider
	AuthenticationRules []Rule
	Logger              func(v ...interface{})
}

func NewMiddleware(configs MiddlewareConfigs) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return &Middleware{
			Handler:             next,
			ASAP:                configs.ASAP,
			PublicKeyProvider:   configs.PublicKeyProvider,
			AuthenticationRules: configs.AuthenticationRules,
			Logger:              configs.Logger,
		}
	}
}

func (mw *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := mw.validateConfigs()
	if err != nil {
		mw.logError("Validation error: %#s", err.Error())
		w.WriteHeader(403)
		return

	}
	route := r.URL.Path
	if !mw.shouldAuth(route) {
		mw.Handler.ServeHTTP(w, r)
		return
	}

	authorization := r.Header.Get(HEADER_AUTHORIZATION)
	if authorization == "" {
		mw.logError("missing authorization header")
		w.WriteHeader(403)
		return
	}

	bearer := REGEXP.ReplaceAllString(authorization, "")
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

	keyID := jwt.(jws.JWS).Protected().Get(HEADER_KEY_ID).(string) // Eww eww eww
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

	mw.Handler.ServeHTTP(w, r)
}

func (mw *Middleware) shouldAuth(route string) bool {
	for _, r := range mw.AuthenticationRules {
		if r.Regexp.MatchString(route) {
			return true
		}
	}
	return false
}

func (mw *Middleware) clientAllowed(route, client string) bool {
	isAllowed := false
	for _, r := range mw.AuthenticationRules {
		if r.Regexp.MatchString(route) {
			isAllowed = r.Clients.Cardinality() == 0 || r.Clients.Contains(client)
			break
		}
	}
	return isAllowed
}

func (mw *Middleware) logError(args ...interface{}) {
	if mw.Logger != nil {
		mw.Logger(args)
	} else {
		log.Print(args)
	}
}

func (mw *Middleware) validateConfigs() error {
	if mw.ASAP == nil {
		return errors.New("ASAP object should be specified in configs.")
	}
	if mw.PublicKeyProvider == nil {
		return errors.New("Public key provider should be specified in configs.")
	}
	return nil
}
