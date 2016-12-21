package asap

import (
	"errors"
	"log"
	"net/http"
	"regexp"

	"bitbucket.org/atlassian/go-asap/keyprovider"
	"github.com/SermoDigital/jose/jws"
	"github.com/deckarep/golang-set"
)

var authPrefixMatcher = regexp.MustCompile("[Bb]earer ")

const headerAuthorization = "Authorization"

// Rule is used for creating rules that define if ASAP authentication should be enabled for the specified routes.
// Routes are matched by provided regular expression. Also a list of allowed clients can be specified.
type Rule struct {
	Regexp  *regexp.Regexp
	Clients mapset.Set
}

// NewRule creates a new Rule object with specified arguments
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

// Middleware is a the struct used for middleware implementation
type Middleware struct {
	Handler             http.Handler
	ASAP                *ASAP
	PublicKeyProvider   keyprovider.PublicKeyProvider
	AuthenticationRules []Rule
	Logger              func(v ...interface{})
}

// MiddlewareConfigs represent configuration parameters used for middleware initialization
type MiddlewareConfigs struct {
	ASAP                *ASAP
	PublicKeyProvider   keyprovider.PublicKeyProvider
	AuthenticationRules []Rule
	Logger              func(v ...interface{})
}

// NewMiddleware creates a new middleware with specified configuration
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

// ServeHTTP implements net/http.Handler
func (mw *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := mw.validateConfigs()
	if err != nil {
		mw.logError("Validation error: %#s", err.Error())
		w.WriteHeader(http.StatusForbidden)
		return

	}
	route := r.URL.Path
	if !mw.shouldAuth(route) {
		mw.Handler.ServeHTTP(w, r)
		return
	}

	authorization := r.Header.Get(headerAuthorization)
	if authorization == "" {
		mw.logError("missing authorization header")
		w.WriteHeader(http.StatusForbidden)
		return
	}

	bearer := authPrefixMatcher.ReplaceAllString(authorization, "")
	jwt, err := mw.ASAP.Parse([]byte(bearer))
	if err != nil {
		mw.logError(err)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	issuer, _ := jwt.Claims().Issuer()
	if !mw.clientAllowed(route, issuer) {
		mw.logError(issuer + " is not authorized for route " + route)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	keyID := jwt.(jws.JWS).Protected().Get(KEY_ID).(string)
	publicKey, err := mw.PublicKeyProvider.GetPublicKey(keyID)
	if err != nil {
		mw.logError(err)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	err = mw.ASAP.Validate(jwt, publicKey)
	if err != nil {
		mw.logError(err)
		w.WriteHeader(http.StatusForbidden)
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
		return errors.New("ASAP object should be specified in configs")
	}
	if mw.PublicKeyProvider == nil {
		return errors.New("Public key provider should be specified in configs")
	}
	return nil
}
