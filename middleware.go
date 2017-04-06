package asap

import (
	"context"
	"fmt"
	"net/http"
)

var ctxKey = struct{}{}

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

// FailedValidationError is used to signal that a given token was parsed
// correctly but failed the validation rules
type FailedValidationError struct {
	Reason error
	Token  Token
}

func (e *FailedValidationError) Error() string {
	return e.Reason.Error()
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
		m.handleError(w, r, &FailedValidationError{Reason: e, Token: token})
		return
	}
	m.wrapped.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey, token)))
}

// FromContext returns the ASAP token for the current request.
func FromContext(ctx context.Context) Token {
	return ctx.Value(ctxKey).(Token)
}
