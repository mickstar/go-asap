package middleware

import (
	"bitbucket.org/drpotato_atlassian/go-asap"
	"bitbucket.org/drpotato_atlassian/go-asap/keyprovider"
	"github.com/SermoDigital/jose/jws"
	"github.com/Sirupsen/logrus"
	"net/http"
	"regexp"
)

var REGEXP = regexp.MustCompile("[Bb]earer ")

const (
	HEADER_AUTHORIZATION = "Authorization"
	HEADER_KEY_ID        = "kid"
)

type ASAPMiddleware struct {
	ASAP              *asap.ASAP
	PublicKeyProvider keyprovider.PublicKeyProvider
}

func (mw *ASAPMiddleware) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
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
