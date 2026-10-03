// Package main implements a differential fuzzer for the migrated asap v2
// module against the jose implementation it replaced.
//
// The jose dependency panics at init on Go >= 1.27, so this harness must run on
// the Go 1.26 toolchain:
//
//	cd tools/difffuzz
//	GOTOOLCHAIN=go1.26.0 go test ./... -v
//	GOTOOLCHAIN=go1.26.0 go run . -n 20000 -seed 1
//
// Each iteration builds one claim set and header, mints it with jose and with
// v2, then feeds the *same* token string to both stacks and compares accept /
// reject verdicts, canonical protected header and canonical claim map. Every
// comparison between the two libraries is at a layer they share: parsing,
// header/claim decoding and raw signature verification.
//
// Three divergences are expected and encoded as passes:
//
//   - jose v0.9.2 signs ES256/384/512 with an ASN.1/DER signature; RFC 7518
//     section 3.4 requires raw R||S, which is what v2 emits. So an ES* token
//     minted by one side never verifies on the other.
//   - HS256 and "none" are outside the ASAP algorithm allow list, so v2's
//     validators reject them by policy while jose's generic verifier accepts
//     well-formed tokens.
//   - error text from inside the JWT libraries is never compared; only the
//     accept / reject verdict is.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"

	josecrypto "github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	josejwt "github.com/SermoDigital/jose/jwt"
	golangjwt "github.com/golang-jwt/jwt/v5"

	asap "bitbucket.org/atlassian/go-asap/v2"
)

const (
	// parityKeysPath is relative to this module's directory, so the harness
	// must be run from tools/difffuzz.
	parityKeysPath = "../../v2/testdata/parity/keys.json"

	// DefaultSeed is the committed, reproducible seed for the bounded test.
	DefaultSeed int64 = 1
	// DefaultN is the committed case count for the bounded test.
	DefaultN int = 2500

	// hmacSecret keys the adversarial HS256 cases. asap rejects HS256 before
	// any key lookup, so the value is never part of ASAP key material.
	hmacSecret = "difffuzz-hs256-secret"

	leeway = time.Second

	// hugeLeeway disables the lifetime check in asap.Token.Validate so the
	// signature-only cross check is not confused by exp/nbf handling.
	hugeLeeway = 100 * 365 * 24 * time.Hour
)

// ---------------------------------------------------------------------- keys

type keyFileEntry struct {
	Alg        string `json:"alg"`
	PrivatePEM string `json:"privatePEM"`
	PublicPEM  string `json:"publicPEM"`
}

type keySet struct {
	priv map[string]any // key name -> *rsa.PrivateKey / *ecdsa.PrivateKey
	pub  map[string]any // key name -> *rsa.PublicKey / *ecdsa.PublicKey
}

func loadKeys(path string) (*keySet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var stored map[string]keyFileEntry
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	ks := &keySet{priv: map[string]any{}, pub: map[string]any{}}
	for name, e := range stored {
		priv, err := asap.NewPrivateKey([]byte(e.PrivatePEM))
		if err != nil {
			return nil, fmt.Errorf("%s: private key: %w", name, err)
		}
		pub, err := asap.NewPublicKey([]byte(e.PublicPEM))
		if err != nil {
			return nil, fmt.Errorf("%s: public key: %w", name, err)
		}
		ks.priv[name] = priv
		ks.pub[name] = pub
	}
	if _, ok := ks.priv["rsa2048"]; !ok {
		return nil, fmt.Errorf("%s: no rsa2048 key", path)
	}
	return ks, nil
}

// ----------------------------------------------------------------- algorithm

// algKey maps a signing algorithm to the fixture key that signs it, mirroring
// tools/paritygen.
var algKey = map[string]string{
	"RS256": "rsa2048", "RS384": "rsa2048", "RS512": "rsa2048",
	"PS256": "rsa2048", "PS384": "rsa2048", "PS512": "rsa2048",
	"ES256": "ec256", "ES384": "ec384", "ES512": "ec512",
}

// asapAlgs are the algorithms v2 has a SigningMethod for, in a fixed order.
var asapAlgs = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
}

// allAlgs additionally contains the adversarial cases.
var allAlgs = append(append([]string{}, asapAlgs...), "HS256", "none")

var ecdsaAlgs = map[string]bool{"ES256": true, "ES384": true, "ES512": true}

func asapMethodForAlg(alg string) (asap.SigningMethod, bool) {
	switch alg {
	case "RS256":
		return asap.SigningMethodRS256, true
	case "RS384":
		return asap.SigningMethodRS384, true
	case "RS512":
		return asap.SigningMethodRS512, true
	case "PS256":
		return asap.SigningMethodPS256, true
	case "PS384":
		return asap.SigningMethodPS384, true
	case "PS512":
		return asap.SigningMethodPS512, true
	case "ES256":
		return asap.SigningMethodES256, true
	case "ES384":
		return asap.SigningMethodES384, true
	case "ES512":
		return asap.SigningMethodES512, true
	}
	return asap.SigningMethod{}, false
}

func joseMethodForAlg(alg string) josecrypto.SigningMethod {
	switch alg {
	case "RS256":
		return josecrypto.SigningMethodRS256
	case "RS384":
		return josecrypto.SigningMethodRS384
	case "RS512":
		return josecrypto.SigningMethodRS512
	case "PS256":
		return josecrypto.SigningMethodPS256
	case "PS384":
		return josecrypto.SigningMethodPS384
	case "PS512":
		return josecrypto.SigningMethodPS512
	case "ES256":
		return josecrypto.SigningMethodES256
	case "ES384":
		return josecrypto.SigningMethodES384
	case "ES512":
		return josecrypto.SigningMethodES512
	case "HS256":
		return josecrypto.SigningMethodHS256
	case "none":
		return josecrypto.Unsecured
	}
	panic("no jose signing method for " + alg)
}

func joseKeyForAlg(alg string, ks *keySet) any {
	switch {
	case alg == "none":
		return nil
	case strings.HasPrefix(alg, "HS"):
		return []byte(hmacSecret)
	default:
		return ks.pub[algKey[alg]]
	}
}

func privKeyForAlg(alg string, ks *keySet) any {
	switch {
	case alg == "none":
		return golangjwt.UnsafeAllowNoneSignatureType
	case strings.HasPrefix(alg, "HS"):
		return []byte(hmacSecret)
	default:
		return ks.priv[algKey[alg]]
	}
}

// --------------------------------------------------------------------- spec

// spec is the exact claim set and protected header an iteration puts on the
// wire. Both minters are driven from it.
type spec struct {
	alg    string
	claims map[string]any
	header map[string]any
}

func randomSpec(rng *rand.Rand, now time.Time) spec {
	return randomSpecForAlg(rng, now, allAlgs[rng.IntN(len(allAlgs))])
}

func randomSpecForAlg(rng *rand.Rand, now time.Time, alg string) spec {
	issVariants := []struct {
		v       string
		present bool
	}{
		{"svc-issuer", true}, {"svc-issuer", true}, {"svc-issuer", true},
		{"", true}, {"svc-issuer/extra", true}, {"iss-ü", true}, {"/", true}, {"a b", true},
		{"svc/issuer", true}, {"svc-issuer/", true},
		{"svc-issuer", false},
	}
	iv := issVariants[rng.IntN(len(issVariants))]
	iss := iv.v

	claims := map[string]any{}
	if iv.present {
		claims["iss"] = iss
	}
	if rng.IntN(4) != 0 {
		claims["jti"] = randomJTI(rng)
	}
	if rng.IntN(6) != 0 {
		iat := []time.Duration{0, -2 * time.Second, -5 * time.Minute, -10 * time.Minute, -2 * time.Hour}
		claims["iat"] = now.Add(iat[rng.IntN(len(iat))]).Unix()
	}
	if rng.IntN(6) != 0 {
		// Offsets stay >= 3s clear of the 1s leeway boundary so a verdict can
		// never flip because the two libraries read the clock a microsecond
		// apart (or because the machine stalls mid-iteration).
		exp := []time.Duration{4 * time.Second, 30 * time.Minute, time.Hour, -4 * time.Second, -5 * time.Minute, -2 * time.Hour, 2 * time.Hour}
		claims["exp"] = now.Add(exp[rng.IntN(len(exp))]).Unix()
	}
	if rng.IntN(3) == 0 {
		nbf := []time.Duration{4 * time.Second, -4 * time.Second, 5 * time.Minute, -5 * time.Minute, time.Minute}
		claims["nbf"] = now.Add(nbf[rng.IntN(len(nbf))]).Unix()
	}
	switch rng.IntN(5) {
	case 0: // aud absent
	case 1:
		claims["aud"] = nil
	case 2:
		claims["aud"] = "aud-one"
	case 3:
		claims["aud"] = []any{"aud-one", "aud-two"}
	default:
		claims["aud"] = []any{"aud-one", "aud-two", "aud-three"}
	}
	addCustomClaims(rng, claims)
	if len(claims) == 0 {
		claims["x"] = "y"
	}

	header := map[string]any{"alg": alg}
	if rng.IntN(8) != 0 {
		header["typ"] = "JWT"
	}
	if kid, present := randomKid(rng, iss); present {
		header["kid"] = kid
	}
	if rng.IntN(8) == 0 {
		header["x-extra"] = "extra"
	}
	return spec{alg: alg, claims: claims, header: header}
}

func randomJTI(rng *rand.Rand) string {
	const hex = "0123456789abcdef"
	var b strings.Builder
	for i := range 32 {
		if i == 8 || i == 12 || i == 16 || i == 20 {
			b.WriteByte('-')
		}
		b.WriteByte(hex[rng.IntN(len(hex))])
	}
	return b.String()
}

func randomKid(rng *rand.Rand, iss string) (any, bool) {
	switch rng.IntN(16) {
	case 0, 1, 2, 3:
		return iss + "/key1", true
	case 4:
		return iss + "/key1/extra", true
	case 5:
		return "other/key1", true // wrong issuer prefix
	case 6:
		return iss + "/../key1", true // path traversal
	case 7:
		return iss + "/./key1", true // dot segment
	case 8:
		return iss + "/key!", true // regexp violation
	case 9:
		return iss + "/ключ", true // non-ASCII
	case 10:
		return iss + "/" + strings.Repeat("a", 4096), true // long but legal
	case 11:
		return "", true // empty
	case 12:
		return float64(5), true // not a string
	case 13:
		return "/key", true // root child
	case 14:
		return iss + "/..key", true // a segment that only starts with dots
	default:
		return nil, false // absent
	}
}

func addCustomClaims(rng *rand.Rand, claims map[string]any) {
	if rng.IntN(2) == 0 {
		scopes := []string{"read:foo", "read:bar", "", "ü"}
		claims["scope"] = scopes[rng.IntN(len(scopes))]
	}
	if rng.IntN(3) == 0 {
		claims["roles"] = []any{"admin", "user"}
	}
	if rng.IntN(4) == 0 {
		claims["mixed"] = []any{"admin", float64(7)}
	}
	if rng.IntN(4) == 0 {
		claims["nested"] = map[string]any{
			"k":    "v",
			"n":    float64(1),
			"deep": map[string]any{"x": []any{float64(1), "z"}},
		}
	}
	if rng.IntN(4) == 0 {
		claims["num"] = float64(rng.IntN(1000)) + 0.5
	}
	if rng.IntN(5) == 0 {
		claims["html"] = "<b>&</b>\u2028emoji:\U0001F600"
	}
	if rng.IntN(6) == 0 {
		claims["ünïcode"] = "ключ"
	}
	if rng.IntN(6) == 0 {
		claims["mixedAud"] = []any{float64(1), "two"}
	}
	if rng.IntN(6) == 0 {
		claims["flag"] = true
	}
	if rng.IntN(6) == 0 {
		claims["neg"] = int64(-9223372036854775807)
	}
}

// ------------------------------------------------------------------- minting

// mintJose signs spec with jose. This is the oracle side of every case.
func mintJose(s spec, ks *keySet) (string, error) {
	claims := jws.Claims{}
	for k, v := range s.claims {
		claims[k] = v
	}
	t := jws.NewJWT(claims, joseMethodForAlg(s.alg))
	j := t.(jws.JWS)
	p := j.Protected()
	for k := range p {
		p.Del(k)
	}
	for k, v := range s.header {
		p.Set(k, v)
	}
	raw, err := t.Serialize(privKeyForAlg(s.alg, ks))
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// mintV2Resign parses a jose token with asap.ParseToken, replaces its claim set
// and protected header with spec, and re-signs it with v2. The parsed token and
// the exposed Claims()/Protected() maps share storage, so the replacement is
// what v2 serialises.
func mintV2Resign(joseToken string, s spec, ks *keySet) (string, error) {
	t, err := asap.ParseToken(joseToken)
	if err != nil {
		return "", err
	}
	c := t.Claims()
	for k := range c {
		delete(c, k)
	}
	for k, v := range s.claims {
		c[k] = v
	}
	h := t.Protected()
	for k := range h {
		delete(h, k)
	}
	for k, v := range s.header {
		h[k] = v
	}
	raw, err := t.Serialize(privKeyForAlg(s.alg, ks))
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// provisionPicks are the random inputs shared by the two provisioner paths.
type provisionPicks struct {
	alg    string
	method asap.SigningMethod
	iss    string
	kid    string
	aud    []string
	ttl    time.Duration
}

func randomProvisionPicks(rng *rand.Rand) provisionPicks {
	alg := asapAlgs[rng.IntN(len(asapAlgs))]
	method, _ := asapMethodForAlg(alg)
	iss := []string{"svc-issuer", "svc-issuer", "", "svc-issuer/extra", "iss-ü"}[rng.IntN(5)]
	kids := []string{
		iss + "/key1", iss + "/key1", iss + "/key1/extra", "other/key1",
		iss + "/../key1", iss + "/key!", iss + "/ключ",
	}
	var aud []string
	switch rng.IntN(4) {
	case 0:
	case 1:
		aud = []string{"aud-one"}
	case 2:
		aud = []string{"aud-one", "aud-two"}
	default:
		aud = []string{"aud-one", "aud-two", "aud-three"}
	}
	ttls := []time.Duration{
		time.Hour, time.Hour - time.Second, time.Hour + time.Second,
		30 * time.Minute, 5 * time.Minute, 2 * time.Hour, -5 * time.Minute,
	}
	return provisionPicks{alg, method, iss, kids[rng.IntN(len(kids))], aud, ttls[rng.IntN(len(ttls))]}
}

// specFromV2Token captures exactly what a provisioned token carries, so jose can
// mint the identical token.
func specFromV2Token(t asap.Token, alg string) spec {
	claims := map[string]any{}
	for k, v := range t.Claims() {
		claims[k] = v
	}
	header := map[string]any{}
	for k, v := range t.Protected() {
		header[k] = v
	}
	return spec{alg: alg, claims: claims, header: header}
}

// mintV2Provision uses the shipped asap.NewProvisioner, then reports the exact
// claim set and header it produced so jose can mint the identical token.
func mintV2Provision(p provisionPicks, ks *keySet) (spec, string, error) {
	t, err := asap.NewProvisioner(p.kid, p.ttl, p.iss, p.aud, p.method).Provision()
	if err != nil {
		return spec{}, "", err
	}
	raw, err := t.Serialize(ks.priv[algKey[p.alg]])
	if err != nil {
		return spec{}, "", err
	}
	return specFromV2Token(t, p.alg), string(raw), nil
}

// staticRotating satisfies asap.AutorotatingKeypairProvider for the
// NewDynamicKeyIDProvisioner path.
type staticRotating struct {
	kid string
	pub any
}

func (p staticRotating) GetKeyID() (string, error) { return p.kid, nil }
func (p staticRotating) Fetch(string) (any, error) { return p.pub, nil }

// mintV2DynamicProvision uses the shipped asap.NewDynamicKeyIDProvisioner. The
// kid is supplied by the provider and is not forced to match the issuer, so this
// path also exercises the kid validator on provisioned tokens.
func mintV2DynamicProvision(p provisionPicks, ks *keySet) (spec, string, error) {
	prov := staticRotating{kid: p.kid, pub: ks.pub[algKey[p.alg]]}
	t, err := asap.NewDynamicKeyIDProvisioner(p.ttl, p.iss, p.aud, p.method, prov).Provision()
	if err != nil {
		return spec{}, "", err
	}
	raw, err := t.Serialize(ks.priv[algKey[p.alg]])
	if err != nil {
		return spec{}, "", err
	}
	return specFromV2Token(t, p.alg), string(raw), nil
}

// ---------------------------------------------------------------- evaluating

type parseOut struct {
	ok     bool
	errMsg string
	header map[string]any
	claims map[string]any
}

func joseParse(token string) parseOut {
	if _, err := jws.ParseJWT([]byte(token)); err != nil {
		return parseOut{errMsg: err.Error()}
	}
	header, _ := decodeSegment(token, 0)
	claims, _ := decodeSegment(token, 1)
	return parseOut{
		ok:     true,
		header: header,
		claims: claims,
	}
}

func v2Parse(token string) parseOut {
	t, err := asap.ParseToken(token)
	if err != nil {
		return parseOut{errMsg: err.Error()}
	}
	return parseOut{
		ok:     true,
		header: map[string]any(t.Protected()),
		claims: map[string]any(t.Claims()),
	}
}

// decodeSegment returns the decoded JSON object of the nth compact-JWS segment.
func decodeSegment(token string, n int) (map[string]any, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[n])
	if err != nil {
		return nil, false
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, false
	}
	return m, true
}

// joseValidate runs jose's Verify plus its registered-claim validation with the
// same 1s leeway as asap's SignatureValidator.
func joseValidate(token, alg string, ks *keySet) (bool, string) {
	jw, err := jws.ParseJWT([]byte(token))
	if err != nil {
		return false, err.Error()
	}
	err = jw.Validate(joseKeyForAlg(alg, ks), joseMethodForAlg(alg), &josejwt.Validator{EXP: leeway, NBF: leeway})
	return err == nil, errString(err)
}

// v2DefaultValidate runs the shipped asap.DefaultValidator.
func v2DefaultValidate(token string) (bool, string) {
	t, err := asap.ParseToken(token)
	if err != nil {
		return false, err.Error()
	}
	err = asap.DefaultValidator.Validate(t)
	return err == nil, errString(err)
}

// v2SigValidate runs the shipped asap.NewSignatureValidator with the default 1s
// leeway, against the fixture key for alg.
func v2SigValidate(token, alg string, ks *keySet) (bool, string) {
	t, err := asap.ParseToken(token)
	if err != nil {
		return false, err.Error()
	}
	err = asap.NewSignatureValidator(staticFetcher{pub: ks.pub[algKey[alg]]}).Validate(t)
	return err == nil, errString(err)
}

// joseVerifySig checks only the raw signature through jose, with the supplied
// key and method. It never consults the kid header.
func joseVerifySig(token, alg string, ks *keySet) bool {
	jw, err := jws.ParseCompact([]byte(token))
	if err != nil {
		return false
	}
	return jw.Verify(joseKeyForAlg(alg, ks), joseMethodForAlg(alg)) == nil
}

// v2VerifySig checks only the raw signature through asap.Token.Validate with the
// supplied key and method, with the lifetime check neutralised. It is the
// apples-to-apples counterpart of joseVerifySig: the kid header is not consulted
// (that happens one layer up, in SignatureValidator).
func v2VerifySig(token, alg string, ks *keySet) (bool, string) {
	method, ok := asapMethodForAlg(alg)
	if !ok {
		return false, "no asap signing method for " + alg
	}
	t, err := asap.ParseToken(token)
	if err != nil {
		return false, err.Error()
	}
	err = t.Validate(ks.pub[algKey[alg]], method, &asap.ValidationOptions{EXP: hugeLeeway, NBF: hugeLeeway})
	return err == nil, errString(err)
}

// v2EngineSigVerify checks the raw signature through the golang-jwt engine v2
// is built on. asap exposes no SigningMethod for HS256/none, so this is the only
// way to show that a jose-minted HMAC token is cryptographically valid and that
// v2's rejection is the algorithm allow list rather than a signature failure.
func v2EngineSigVerify(token, alg string) bool {
	var methods []string
	var key any
	switch alg {
	case "HS256":
		methods = []string{"HS256"}
		key = []byte(hmacSecret)
	case "none":
		methods = []string{"none"}
		key = golangjwt.UnsafeAllowNoneSignatureType
	default:
		return false
	}
	p := golangjwt.NewParser(golangjwt.WithValidMethods(methods), golangjwt.WithoutClaimsValidation())
	_, err := p.Parse(token, func(*golangjwt.Token) (any, error) { return key, nil })
	return err == nil
}

type staticFetcher struct{ pub any }

func (f staticFetcher) Fetch(string) (any, error) { return f.pub, nil }

// ---------------------------------------------------------------- prediction

// getTime mirrors asap.Claims.GetTime for the types that reach it.
func getTime(m map[string]any, key string) (time.Time, bool) {
	switch t := m[key].(type) {
	case int:
		return time.Unix(int64(t), 0), true
	case int32:
		return time.Unix(int64(t), 0), true
	case int64:
		return time.Unix(t, 0), true
	case uint:
		if uint64(t) > math.MaxInt64 {
			return time.Time{}, false
		}
		return time.Unix(int64(t), 0), true
	case uint32:
		return time.Unix(int64(t), 0), true
	case uint64:
		if t > math.MaxInt64 {
			return time.Time{}, false
		}
		return time.Unix(int64(t), 0), true
	case float64:
		return time.Unix(int64(t), 0), true
	default:
		return time.Time{}, false
	}
}

// timeOK mirrors asap.Claims.validateTime / jose's Claims.Validate.
func timeOK(claims map[string]any, now time.Time, l time.Duration) bool {
	if exp, ok := getTime(claims, "exp"); ok {
		if now.After(exp.Add(l)) {
			return false
		}
	}
	if nbf, ok := getTime(claims, "nbf"); ok {
		if !now.After(nbf.Add(-l)) {
			return false
		}
	}
	return true
}

// timeBoundary reports whether exp or nbf sits within the safety window of its
// 1s leeway decision point, where a verdict could flip between the two clock
// reads. Generation keeps offsets well clear of it; this is belt and braces for
// a stalled machine.
func timeBoundary(claims map[string]any, now time.Time) bool {
	const safety = 2 * time.Second
	if exp, ok := getTime(claims, "exp"); ok {
		if d := now.Sub(exp.Add(leeway)); absDuration(d) < safety {
			return true
		}
	}
	if nbf, ok := getTime(claims, "nbf"); ok {
		if d := now.Sub(nbf.Add(-leeway)); absDuration(d) < safety {
			return true
		}
	}
	return false
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

var kidRe = regexp.MustCompile(`^[\w.\-\+/]*$`)

// kidOK mirrors asap's KidValidator.
func kidOK(header, claims map[string]any) bool {
	kid, ok := header["kid"].(string)
	if !ok {
		return false
	}
	issuer, _ := claims["iss"].(string)
	if !strings.HasPrefix(kid, issuer+"/") {
		return false
	}
	for s := range strings.SplitSeq(kid, "/") {
		if s == "." || s == ".." {
			return false
		}
	}
	return kidRe.MatchString(kid)
}

func algAllowed(alg string) bool {
	_, ok := algKey[alg]
	return ok
}

// expirationOK mirrors asap's ExpirationValidator.
func expirationOK(claims map[string]any) bool {
	iat, ok := getTime(claims, "iat")
	if !ok {
		return false
	}
	exp, _ := getTime(claims, "exp")
	return !iat.Add(time.Hour).Before(exp)
}

// requiredOK mirrors asap.DefaultValidator's required-claim set.
func requiredOK(claims map[string]any) bool {
	for _, name := range []string{"iss", "exp", "iat", "aud", "jti"} {
		if _, ok := claims[name]; !ok {
			return false
		}
	}
	return true
}

func predictDefault(header, claims map[string]any, alg string) bool {
	return kidOK(header, claims) && algAllowed(alg) && expirationOK(claims) && requiredOK(claims)
}

// sigValidV2 reports whether v2's signature check succeeds for a token minted
// by the given side.
func sigValidV2(alg, mintedBy string) bool {
	if !algAllowed(alg) {
		return false
	}
	if ecdsaAlgs[alg] && mintedBy == "jose" {
		return false // jose's DER signature is not RFC 7518 compliant
	}
	return true
}

func sigValidJose(alg, mintedBy string) bool {
	if ecdsaAlgs[alg] && mintedBy == "v2" {
		return false // jose only accepts its own DER form
	}
	return true
}

func predictV2Sig(header, claims map[string]any, alg, mintedBy string, now time.Time) bool {
	_, kidIsString := header["kid"].(string)
	return kidIsString && algAllowed(alg) && sigValidV2(alg, mintedBy) && timeOK(claims, now, leeway)
}

func predictJoseSig(claims map[string]any, alg, mintedBy string, now time.Time) bool {
	return sigValidJose(alg, mintedBy) && timeOK(claims, now, leeway)
}

// ------------------------------------------------------------------- report

type divergence struct {
	Seed     int64  `json:"seed"`
	Iter     int    `json:"iteration"`
	Alg      string `json:"alg"`
	MintedBy string `json:"mintedBy"`
	Kind     string `json:"kind"`
	Detail   string `json:"detail,omitempty"`
	Token    string `json:"token,omitempty"`
	JoseErr  string `json:"joseErr,omitempty"`
	V2Err    string `json:"v2Err,omitempty"`
}

type report struct {
	Seed        int64
	Iterations  int
	Tokens      int
	AlgCount    map[string]int
	Divergences []divergence

	// documented, expected cross-library verdict differences
	ExpectedECDSA  int
	ExpectedPolicy int
	// ExpectedUnresolvableKid counts tokens whose kid is absent or not a string,
	// where NewSignatureValidator cannot resolve a key while jose's Validate
	// verifies with the key handed to it.
	ExpectedUnresolvableKid int
	// TimeBoundarySkipped counts tokens whose exp/nbf sat inside the safety
	// window, so their time-dependent verdicts were not compared.
	TimeBoundarySkipped int
	// cross-library verdict mismatches that are not documented
	CrossMismatches int
}

func (r *report) add(d divergence) { r.Divergences = append(r.Divergences, d) }

// --------------------------------------------------------------------- run

// run drives n seeded iterations and returns the accumulated report.
func run(n int, seed int64) *report {
	ks, err := loadKeys(parityKeysPath)
	if err != nil {
		panic(err)
	}
	rng := rand.New(rand.NewPCG(uint64(seed), uint64(seed)*0x9E3779B97F4A7C15))
	rep := &report{Seed: seed, AlgCount: map[string]int{}}

	for i := range n {
		now := time.Now().UTC()
		var s spec
		var tokenJ, tokenV string

		switch r := rng.IntN(20); r {
		case 0, 1:
			// Provisioner paths: v2 mints, jose mirrors the exact claims.
			picks := randomProvisionPicks(rng)
			var err error
			if r == 0 {
				s, tokenV, err = mintV2DynamicProvision(picks, ks)
			} else {
				s, tokenV, err = mintV2Provision(picks, ks)
			}
			if err != nil {
				panic(fmt.Sprintf("iteration %d: v2 provision: %v", i, err))
			}
			tokenJ, err = mintJose(s, ks)
			if err != nil {
				panic(fmt.Sprintf("iteration %d: jose mirror: %v", i, err))
			}
		default:
			s = randomSpec(rng, now)
			var err error
			tokenJ, err = mintJose(s, ks)
			if err != nil {
				panic(fmt.Sprintf("iteration %d: jose mint: %v", i, err))
			}
			tokenV, err = mintV2Resign(tokenJ, s, ks)
			if err != nil {
				panic(fmt.Sprintf("iteration %d: v2 re-sign: %v", i, err))
			}
		}

		rep.Iterations++
		rep.AlgCount[s.alg]++

		evals := []tokenEval{
			evaluate(i, seed, s, "jose", tokenJ, ks),
			evaluate(i, seed, s, "v2", tokenV, ks),
		}
		rep.Tokens += len(evals)
		for _, e := range evals {
			checkToken(rep, e)
		}
		checkPair(rep, evals[0], evals[1])
	}
	return rep
}

type tokenEval struct {
	iter     int
	seed     int64
	spec     spec
	mintedBy string
	token    string

	joseParse parseOut
	v2Parse   parseOut

	joseOK  bool
	joseErr string
	v2DefOK bool
	v2DefE  string
	v2SigOK bool
	v2SigE  string

	// signature-only verdicts (no kid lookup, lifetime neutralised)
	joseRawSig bool
	v2RawSig   bool
	v2RawSigE  string

	now time.Time
}

func evaluate(iter int, seed int64, s spec, mintedBy, token string, ks *keySet) tokenEval {
	e := tokenEval{
		iter:      iter,
		seed:      seed,
		spec:      s,
		mintedBy:  mintedBy,
		token:     token,
		joseParse: joseParse(token),
		v2Parse:   v2Parse(token),
		now:       time.Now().UTC(),
	}
	e.joseOK, e.joseErr = joseValidate(token, s.alg, ks)
	e.v2DefOK, e.v2DefE = v2DefaultValidate(token)
	e.v2SigOK, e.v2SigE = v2SigValidate(token, s.alg, ks)
	e.joseRawSig = joseVerifySig(token, s.alg, ks)
	e.v2RawSig, e.v2RawSigE = v2VerifySig(token, s.alg, ks)
	return e
}

func (e tokenEval) div(kind, detail string) divergence {
	return divergence{
		Seed:     e.seed,
		Iter:     e.iter,
		Alg:      e.spec.alg,
		MintedBy: e.mintedBy,
		Kind:     kind,
		Detail:   detail,
		Token:    e.token,
		JoseErr:  e.joseErr,
		V2Err:    firstNonEmpty(e.v2SigE, e.v2DefE),
	}
}

func checkToken(rep *report, e tokenEval) {
	// 1. Parse verdicts must agree between jose and v2.
	if e.joseParse.ok != e.v2Parse.ok {
		rep.add(e.div("parse-verdict", fmt.Sprintf("jose=%v (%s) v2=%v (%s)",
			e.joseParse.ok, e.joseParse.errMsg, e.v2Parse.ok, e.v2Parse.errMsg)))
		return
	}
	if !e.joseParse.ok {
		return
	}
	// 2. Canonical header and claims must be identical.
	if !reflect.DeepEqual(e.joseParse.header, e.v2Parse.header) {
		rep.add(e.div("header", fmt.Sprintf("jose=%v v2=%v", e.joseParse.header, e.v2Parse.header)))
	}
	if !reflect.DeepEqual(e.joseParse.claims, e.v2Parse.claims) {
		rep.add(e.div("claims", fmt.Sprintf("jose=%v v2=%v", e.joseParse.claims, e.v2Parse.claims)))
	}

	// 3. asap's own validators must match an independent prediction derived
	// from the claim set and the documented signature matrix.
	if got := predictDefault(e.v2Parse.header, e.v2Parse.claims, e.spec.alg); e.v2DefOK != got {
		rep.add(e.div("v2-default", fmt.Sprintf("DefaultValidator=%v want %v (err=%s)", e.v2DefOK, got, e.v2DefE)))
	}
	if timeBoundary(e.v2Parse.claims, e.now) {
		rep.TimeBoundarySkipped++
	} else {
		if got := predictV2Sig(e.v2Parse.header, e.v2Parse.claims, e.spec.alg, e.mintedBy, e.now); e.v2SigOK != got {
			rep.add(e.div("v2-sig", fmt.Sprintf("SignatureValidator=%v want %v (err=%s)", e.v2SigOK, got, e.v2SigE)))
		}
		if got := predictJoseSig(e.v2Parse.claims, e.spec.alg, e.mintedBy, e.now); e.joseOK != got {
			rep.add(e.div("jose-sig", fmt.Sprintf("jose Validate=%v want %v (err=%s)", e.joseOK, got, e.joseErr)))
		}
	}

	// 4. Signature-only cross check: same token, same key, no kid lookup and no
	// lifetime rules, so the only thing left that can differ is the signature
	// encoding itself.
	if algAllowed(e.spec.alg) {
		wantJose := sigValidJose(e.spec.alg, e.mintedBy)
		wantV2 := sigValidV2(e.spec.alg, e.mintedBy)
		if e.joseRawSig != wantJose {
			rep.add(e.div("jose-rawsig", fmt.Sprintf("jose Verify=%v want %v", e.joseRawSig, wantJose)))
		}
		if e.v2RawSig != wantV2 {
			rep.add(e.div("v2-rawsig", fmt.Sprintf("asap Token.Validate=%v want %v (err=%s)", e.v2RawSig, wantV2, e.v2RawSigE)))
		}
		if e.joseRawSig != e.v2RawSig {
			if ecdsaAlgs[e.spec.alg] {
				rep.ExpectedECDSA++
			} else {
				rep.CrossMismatches++
				rep.add(e.div("sig-cross", fmt.Sprintf("v2 Token.Validate=%v jose Verify=%v", e.v2RawSig, e.joseRawSig)))
			}
		}
	} else {
		// HS256 and none: v2 has no SigningMethod for them, so the raw signature
		// is checked through the golang-jwt engine v2 delegates to. The signature
		// must be valid; the asap validators reject the algorithm by policy.
		if !e.joseRawSig {
			rep.add(e.div("jose-rawsig", "jose Verify rejected a well-formed "+e.spec.alg+" token"))
		}
		if !v2EngineSigVerify(e.token, e.spec.alg) {
			rep.add(e.div("v2-engine", fmt.Sprintf("golang-jwt rejected a %s token v2 parsed", e.spec.alg)))
		}
		rep.ExpectedPolicy++
	}

	// 5. When the kid is not a string, NewSignatureValidator cannot resolve a
	// key, so its full verdict legitimately differs from jose's key-in-hand
	// Validate. Count it rather than treat it as a mismatch.
	if _, kidIsString := e.v2Parse.header["kid"].(string); !kidIsString {
		rep.ExpectedUnresolvableKid++
	}
}

// checkPair asserts the invariants that must hold between the jose-minted and
// v2-minted token of the same iteration: identical header and claims make the
// signature-independent validator verdicts identical, and signature verdicts
// are identical except for the documented ECDSA encoding divergence.
func checkPair(rep *report, j, v tokenEval) {
	if !j.v2Parse.ok || !v.v2Parse.ok {
		return
	}
	if j.v2DefOK != v.v2DefOK {
		rep.add(j.div("default-cross", fmt.Sprintf("jose-minted=%v v2-minted=%v", j.v2DefOK, v.v2DefOK)))
	}
	if j.v2SigOK != v.v2SigOK && !ecdsaAlgs[j.spec.alg] {
		rep.add(j.div("sig-cross-pair", fmt.Sprintf("jose-minted=%v v2-minted=%v", j.v2SigOK, v.v2SigOK)))
	}
}

// ------------------------------------------------------------------- helpers

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
