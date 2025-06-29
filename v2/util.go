package asap

import (
	"github.com/SermoDigital/jose/jws"
	"github.com/pkg/errors"
)

func GetKeyIDFromToken(token Token) (string, error) {
	keyID, ok := token.(jws.JWS).Protected().Get(ClaimKeyID).(string)
	if !ok {
		return "", errors.New("Failed to get the keyID from the token")
	}

	return keyID, nil
}
