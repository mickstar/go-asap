package asap

import (
	"fmt"
	"net/http"
)

type middleware struct {
	validator Validator
	callback  func(http.ResponseWriter, *http.Request, error)
	wrapped   http.Handler
}

// NewMiddleware generates a func(http.Handler) http.Handler that validates
// all incoming requests. An optional callback can be provided to handle
// validation failure. If nil, the middleware will respond with a 403.
func NewMiddleware(validator Validator, callback func(http.ResponseWriter, *http.Request, error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return &middleware{validator, callback, next}
	}
}

func (m *middleware) handleError(w http.ResponseWriter, r *http.Request, e error) {
	if m.callback == nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	m.callback(w, r, e)
	return
}

func (m *middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var bearer = r.Header.Get("Authorization")
	if len(bearer) < len("Bearer ") {
		m.handleError(w, r, fmt.Errorf("Missing bearer string"))
		return
	}
	var rawToken = bearer[len("Bearer "):]
	var token, e = ParseToken(rawToken)
	if e != nil {
		m.handleError(w, r, e)
		return
	}
	e = m.validator.Validate(token)
	if e != nil {
		m.handleError(w, r, e)
		return
	}
	m.wrapped.ServeHTTP(w, r)
}
