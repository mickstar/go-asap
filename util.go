package asap

import "errors"

// GetKeyIDFromToken returns the "kid" protected header of the given token.
func GetKeyIDFromToken(token Token) (string, error) {
	header := token.Protected()
	if header == nil {
		return "", errors.New("Protected header is nil")
	}

	rawKeyID := header.Get(ClaimKeyID)
	if rawKeyID == nil {
		return "", errors.New("Missing the kid header")
	}

	keyID, ok := rawKeyID.(string)
	if !ok {
		return "", errors.New("kid header value is not a string")
	}

	return keyID, nil
}
