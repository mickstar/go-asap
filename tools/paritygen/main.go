// Command paritygen freezes the pre-migration behaviour of the jose-based asap
// library into committed fixtures.
//
// The jose dependency panics at init on Go >= 1.27, so it cannot be used as a
// live oracle after the migration. This generator must therefore be run once,
// before the migration, on the Go 1.26 toolchain, and its output committed:
//
//	cd tools/paritygen
//	GOTOOLCHAIN=go1.26.0 go run . -out ../../v2/testdata/parity
//
// The command reuses keys.json when it already exists, so committed key
// material stays valid. It is NOT byte-for-byte reproducible: jose randomises
// ECDSA and RSA-PSS signatures, so every ES*/PS* token changes on each run, and
// the validation fixtures are anchored at the generation instant. Treat the
// committed fixtures as frozen and re-run only when fixture content has to
// change deliberately.
//
// It records two kinds of fixture:
//
//   - wire.json: raw tokens plus exactly what jose's parser makes of them
//     (parse ok/err, protected header, claims). Time-independent.
//   - validation.json: raw tokens plus the verdict of the *actual* shipped asap
//     validators (DefaultValidator, NewSignatureValidator) and of jose's own
//     Validate, anchored at a fixed `anchor` instant so the post-migration test
//     can reproduce them with an injected clock.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	josecrypto "github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	josejwt "github.com/SermoDigital/jose/jwt"

	asap "bitbucket.org/atlassian/go-asap/v2"
)

const issuer = "svc-issuer"

type keyEntry struct {
	Alg        string `json:"alg"`
	PrivatePEM string `json:"privatePEM"`
	PublicPEM  string `json:"publicPEM"`
}

type keySet struct {
	priv map[string]any
	pub  map[string]any
	meth map[string]josecrypto.SigningMethod
}

type wireCase struct {
	Name     string          `json:"name"`
	Token    string          `json:"token"`
	MintedBy string          `json:"mintedBy"`
	ParseOK  bool            `json:"joseParseOK"`
	ParseErr string          `json:"joseParseErr,omitempty"`
	Header   json.RawMessage `json:"joseHeader,omitempty"`
	Claims   json.RawMessage `json:"joseClaims,omitempty"`
	Note     string          `json:"note,omitempty"`
}

type validCase struct {
	Name  string `json:"name"`
	Token string `json:"token"`
	// Method/Key identify the key material used during validation. Both empty
	// means DefaultValidator only (no SignatureValidator in the chain).
	Method string `json:"method,omitempty"`
	Key    string `json:"key,omitempty"`

	DefaultOK    bool   `json:"asapDefaultOK"`
	DefaultErr   string `json:"asapDefaultErr,omitempty"`
	SigOK        bool   `json:"asapSigOK"`
	SigErr       string `json:"asapSigErr,omitempty"`
	JoseValidOK  bool   `json:"joseValidateOK"`
	JoseValidErr string `json:"joseValidateErr,omitempty"`

	// AudienceOK records NewAllowedAudienceValidator("aud-one"), which is the
	// validator that consumes Claims.Audience(). RolesOK records
	// NewAllowedClaimValuesValidator("roles", "writer"), which consumes a JSON
	// array claim.
	AudienceOK bool `json:"asapAudienceOK"`
	RolesOK    bool `json:"asapRolesOK"`

	ExpectValid bool   `json:"expectValid"`
	Note        string `json:"note,omitempty"`
}

func main() {
	out := flag.String("out", "../../v2/testdata/parity", "output directory for fixtures")
	flag.Parse()

	if err := os.MkdirAll(*out, 0o755); err != nil {
		fatal(err)
	}

	keys, err := loadOrCreateKeys(filepath.Join(*out, "keys.json"))
	if err != nil {
		fatal(err)
	}

	anchor := time.Now().UTC().Truncate(time.Second)

	wire, err := buildWire(keys)
	if err != nil {
		fatal(err)
	}
	validation, err := buildValidation(keys, anchor)
	if err != nil {
		fatal(err)
	}

	meta := map[string]any{
		"version":   1,
		"generator": "github.com/mickstar/go-asap/tools/paritygen",
		// The asap* verdict fields are recorded from THIS library, which is the
		// pre-migration implementation still linked against jose. It is extracted
		// from commit 97f05bd by `make parity-oracle`; naming it here is what makes
		// those fields evidence about the old behaviour instead of a self-portrait
		// of the library under test.
		"oracleLibrary": "bitbucket.org/atlassian/go-asap/v2 (pre-migration, jose-based)",
		"oracleCommit":  "97f05bd",
		"joseVersion":   "v0.9.2-0.20161205224733-f6df55f235c2",
		"goToolchain":   "go1.26.0",
		"anchor":        anchor.Format(time.RFC3339),
		"wireCases":     len(wire),
		"validCases":    len(validation),
	}
	for name, v := range map[string]any{"meta.json": meta, "wire.json": wire, "validation.json": validation} {
		if err := writeJSON(filepath.Join(*out, name), v); err != nil {
			fatal(err)
		}
	}

	fmt.Printf("wrote %d wire cases, %d validation cases to %s (anchor %s)\n",
		len(wire), len(validation), *out, anchor.Format(time.RFC3339))
}

// ---------------------------------------------------------------- key material

func loadOrCreateKeys(path string) (*keySet, error) {
	if raw, err := os.ReadFile(path); err == nil {
		var stored map[string]keyEntry
		if err := json.Unmarshal(raw, &stored); err == nil {
			if ks, err := parseKeySet(stored); err == nil {
				fmt.Println("reusing existing keys.json")
				return ks, nil
			}
		}
	}

	stored := map[string]keyEntry{}
	ks := newKeySet()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	registerRSA(stored, ks, "rsa2048", rsaKey)

	curves := []struct {
		name string
		alg  string
		c    elliptic.Curve
		m    josecrypto.SigningMethod
	}{
		{"ec256", "ES256", elliptic.P256(), josecrypto.SigningMethodES256},
		{"ec384", "ES384", elliptic.P384(), josecrypto.SigningMethodES384},
		{"ec512", "ES512", elliptic.P521(), josecrypto.SigningMethodES512},
	}
	for _, cv := range curves {
		ecKey, err := ecdsa.GenerateKey(cv.c, rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalECPrivateKey(ecKey)
		if err != nil {
			return nil, err
		}
		pubDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
		if err != nil {
			return nil, err
		}
		stored[cv.name] = keyEntry{
			Alg:        cv.alg,
			PrivatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})),
			PublicPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})),
		}
		ks.priv[cv.name] = ecKey
		ks.pub[cv.name] = &ecKey.PublicKey
		ks.meth[cv.alg] = cv.m
	}

	if err := writeJSON(path, stored); err != nil {
		return nil, err
	}
	return ks, nil
}

func newKeySet() *keySet {
	return &keySet{priv: map[string]any{}, pub: map[string]any{}, meth: map[string]josecrypto.SigningMethod{}}
}

func registerRSA(stored map[string]keyEntry, ks *keySet, name string, k *rsa.PrivateKey) {
	if stored != nil {
		pubDER, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			panic(err)
		}
		stored[name] = keyEntry{
			Alg:        "RS256",
			PrivatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})),
			PublicPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})),
		}
	}
	ks.priv[name] = k
	ks.pub[name] = &k.PublicKey
	for _, alg := range []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"} {
		ks.meth[alg] = rsaMethod(alg)
	}
}

func rsaMethod(alg string) josecrypto.SigningMethod {
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
	}
	panic("unknown rsa method " + alg)
}

func parseKeySet(stored map[string]keyEntry) (*keySet, error) {
	ks := newKeySet()
	var rsaKey *rsa.PrivateKey
	for name, e := range stored {
		block, _ := pem.Decode([]byte(e.PrivatePEM))
		if block == nil {
			return nil, fmt.Errorf("%s: no PEM block", name)
		}
		pb, _ := pem.Decode([]byte(e.PublicPEM))
		if pb == nil {
			return nil, fmt.Errorf("%s: no public PEM block", name)
		}
		pub, err := x509.ParsePKIXPublicKey(pb.Bytes)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(name, "rsa") {
			k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			rsaKey = k
			ks.priv[name] = k
			ks.pub[name] = pub
			continue
		}
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ks.priv[name] = k
		ks.pub[name] = pub
		ks.meth[e.Alg] = mapAlg(e.Alg)
	}
	if rsaKey == nil {
		return nil, fmt.Errorf("no rsa key in keys.json")
	}
	registerRSA(nil, ks, "rsa2048", rsaKey)
	return ks, nil
}

func mapAlg(alg string) josecrypto.SigningMethod {
	switch alg {
	case "ES256":
		return josecrypto.SigningMethodES256
	case "ES384":
		return josecrypto.SigningMethodES384
	case "ES512":
		return josecrypto.SigningMethodES512
	}
	return rsaMethod(alg)
}

// ------------------------------------------------------------------- minting

type mintOpts struct {
	alg     string
	key     string
	kid     any // nil = issuer+"/key1"
	omitKid bool
	omitTyp bool
	iss     string
	omitIss bool
	jti     string
	omitJTI bool
	aud     []string
	omitAud bool
	iat     *time.Time
	omitIAT bool
	exp     *time.Time
	omitEXP bool
	nbf     *time.Time
	extra   map[string]any
}

func mint(ks *keySet, o mintOpts) (string, error) {
	claims := jws.Claims{}
	if !o.omitIss {
		claims.SetIssuer(o.iss)
	}
	if !o.omitJTI {
		claims.SetJWTID(o.jti)
	}
	if !o.omitIAT && o.iat != nil {
		claims.SetIssuedAt(*o.iat)
	}
	if !o.omitEXP && o.exp != nil {
		claims.SetExpiration(*o.exp)
	}
	if o.nbf != nil {
		claims.SetNotBefore(*o.nbf)
	}
	if !o.omitAud && len(o.aud) > 0 {
		claims.SetAudience(o.aud...)
	}
	for k, v := range o.extra {
		claims.Set(k, v)
	}

	t := jws.NewJWT(claims, ks.meth[o.alg])
	signed := t.(jws.JWS)
	if !o.omitKid {
		if o.kid != nil {
			signed.Protected().Set("kid", o.kid)
		} else {
			signed.Protected().Set("kid", o.iss+"/key1")
		}
	}
	if o.omitTyp {
		signed.Protected().Del("typ")
	}
	raw, err := t.Serialize(ks.priv[o.key])
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// -------------------------------------------------------------- wire fixtures

func buildWire(ks *keySet) ([]wireCase, error) {
	fixedIAT := time.Unix(1704067200, 0).UTC() // 2024-01-01T00:00:00Z
	fixedEXP := fixedIAT.Add(time.Hour)

	var cases []wireCase

	algs := []struct{ alg, key string }{
		{"RS256", "rsa2048"}, {"RS384", "rsa2048"}, {"RS512", "rsa2048"},
		{"PS256", "rsa2048"}, {"PS384", "rsa2048"}, {"PS512", "rsa2048"},
		{"ES256", "ec256"}, {"ES384", "ec384"}, {"ES512", "ec512"},
	}
	for _, a := range algs {
		base := mintOpts{alg: a.alg, key: a.key, iss: issuer, jti: "11111111-2222-3333-4444-555555555555",
			aud: []string{"aud-one"}, iat: &fixedIAT, exp: &fixedEXP}

		tok, err := mint(ks, base)
		if err != nil {
			return nil, err
		}
		cases = append(cases, record(tok, "jose", a.alg+" single aud"))

		multi := base
		multi.aud = []string{"aud-one", "aud-two"}
		tok, err = mint(ks, multi)
		if err != nil {
			return nil, err
		}
		cases = append(cases, record(tok, "jose", a.alg+" multi aud"))

		noaud := base
		noaud.omitAud = true
		tok, err = mint(ks, noaud)
		if err != nil {
			return nil, err
		}
		cases = append(cases, record(tok, "jose", a.alg+" no aud"))
	}

	headerVariants := []struct {
		name string
		o    mintOpts
	}{
		{"kid_missing", mintOpts{alg: "RS256", key: "rsa2048", iss: issuer, jti: "j", aud: []string{"aud-one"}, iat: &fixedIAT, exp: &fixedEXP, omitKid: true}},
		{"kid_empty", mintOpts{alg: "RS256", key: "rsa2048", iss: issuer, jti: "j", aud: []string{"aud-one"}, iat: &fixedIAT, exp: &fixedEXP, kid: ""}},
		{"kid_non_string", mintOpts{alg: "RS256", key: "rsa2048", iss: issuer, jti: "j", aud: []string{"aud-one"}, iat: &fixedIAT, exp: &fixedEXP, kid: float64(5)}},
		{"kid_no_issuer_prefix", mintOpts{alg: "RS256", key: "rsa2048", iss: issuer, jti: "j", aud: []string{"aud-one"}, iat: &fixedIAT, exp: &fixedEXP, kid: "other/key"}},
		{"kid_traversal", mintOpts{alg: "RS256", key: "rsa2048", iss: issuer, jti: "j", aud: []string{"aud-one"}, iat: &fixedIAT, exp: &fixedEXP, kid: issuer + "/../key"}},
		{"kid_dot_segment", mintOpts{alg: "RS256", key: "rsa2048", iss: issuer, jti: "j", aud: []string{"aud-one"}, iat: &fixedIAT, exp: &fixedEXP, kid: issuer + "/./key"}},
		{"kid_invalid_chars", mintOpts{alg: "RS256", key: "rsa2048", iss: issuer, jti: "j", aud: []string{"aud-one"}, iat: &fixedIAT, exp: &fixedEXP, kid: issuer + "/key!"}},
		{"kid_unicode", mintOpts{alg: "RS256", key: "rsa2048", iss: issuer, jti: "j", aud: []string{"aud-one"}, iat: &fixedIAT, exp: &fixedEXP, kid: issuer + "/ключ"}},
		{"kid_long", mintOpts{alg: "RS256", key: "rsa2048", iss: issuer, jti: "j", aud: []string{"aud-one"}, iat: &fixedIAT, exp: &fixedEXP, kid: issuer + "/" + strings.Repeat("a", 4096)}},
		{"typ_missing", mintOpts{alg: "RS256", key: "rsa2048", iss: issuer, jti: "j", aud: []string{"aud-one"}, iat: &fixedIAT, exp: &fixedEXP, omitTyp: true}},
		{"iss_unicode", mintOpts{alg: "RS256", key: "rsa2048", iss: "iss-ü", jti: "j", aud: []string{"aud-one"}, iat: &fixedIAT, exp: &fixedEXP, kid: "iss-ü/key"}},
		{"iss_empty", mintOpts{alg: "RS256", key: "rsa2048", iss: "", jti: "j", aud: []string{"aud-one"}, iat: &fixedIAT, exp: &fixedEXP, kid: "/key"}},
	}
	for _, hv := range headerVariants {
		tok, err := mint(ks, hv.o)
		if err != nil {
			return nil, err
		}
		cases = append(cases, record(tok, "jose", "header variant "+hv.name))
	}

	handcrafted := []struct {
		name  string
		token string
	}{
		{"alg_none", handcraft(`{"alg":"none","typ":"JWT"}`, `{"iss":"svc-issuer","aud":"aud-one"}`)},
		{"alg_unknown", handcraft(`{"alg":"XX999","typ":"JWT"}`, `{"iss":"svc-issuer"}`)},
		{"alg_absent", handcraft(`{"typ":"JWT","kid":"svc-issuer/key1"}`, `{"iss":"svc-issuer"}`)},
		{"alg_hs256_confusion", mustMintHS256()},
		{"empty_string", ""},
		{"one_part", "abc"},
		{"two_parts", "abc.def"},
		{"four_parts", "abc.def.ghi.jkl"},
		{"payload_not_json", b64(`{"alg":"RS256"}`) + "." + b64(`not-json`) + ".AAAA"},
		{"payload_not_object", b64(`{"alg":"RS256"}`) + "." + b64(`[1,2,3]`) + ".AAAA"},
		{"duplicate_json_keys", b64(`{"alg":"RS256"}`) + "." + b64(`{"iss":"a","iss":"b"}`) + ".AAAA"},
		{"header_not_object", b64(`[1,2]`) + "." + b64(`{"iss":"a"}`) + ".AAAA"},
		{"padded_base64", b64pad(`{"alg":"RS256"}`) + "." + b64pad(`{"iss":"a"}`) + ".AAAA"},
		{"whitespace_around", " " + b64(`{"alg":"RS256"}`) + "." + b64(`{"iss":"a"}`) + ".AAAA "},
		{"signature_empty", b64(`{"alg":"RS256"}`) + "." + b64(`{"iss":"a"}`) + "."},
	}

	for _, hc := range handcrafted {
		cases = append(cases, record(hc.token, "handcrafted", hc.name))
	}

	sort.SliceStable(cases, func(i, j int) bool { return cases[i].Name < cases[j].Name })
	return cases, nil
}

func record(token, mintedBy, name string) wireCase {
	c := wireCase{Name: sanitize(name), Token: token, MintedBy: mintedBy}
	parsed, err := jws.ParseJWT([]byte(token))
	if err != nil {
		c.ParseErr = err.Error()
		return c
	}
	c.ParseOK = true
	if v, ok := decodeSegment(token, 0); ok {
		if _, isObject := v.(map[string]any); isObject {
			c.Header = canonicalJSON(v)
		}
	}
	c.Claims = canonicalJSON(parsed.Claims())
	return c
}

// decodeSegment returns the decoded JSON value of the nth compact-JWS segment.
func decodeSegment(token string, n int) (any, bool) {
	parts := strings.Split(token, ".")
	if len(parts) <= n {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[n])
	if err != nil {
		return nil, false
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, false
	}
	return v, true
}

// -------------------------------------------------------- validation fixtures

func buildValidation(ks *keySet, anchor time.Time) ([]validCase, error) {
	const m = time.Minute
	var cases []validCase

	// Verdicts are recorded, not asserted against my own expectation: the
	// shipped library is the oracle. expectValid is a sanity check on the matrix
	// itself and a generation-time failure if the construction is wrong.
	add := func(name, token, method, key string, expectValid bool, note string) error {
		c := validCase{Name: name, Token: token, Method: method, Key: key, ExpectValid: expectValid, Note: note}
		vt, err := asap.ParseToken(token)
		if err != nil {
			return fmt.Errorf("%s: asap.ParseToken: %w", name, err)
		}
		e := asap.DefaultValidator.Validate(vt)
		c.DefaultOK = e == nil
		c.DefaultErr = errString(e)

		c.AudienceOK = asap.NewAllowedAudienceValidator("aud-one").Validate(vt) == nil
		c.RolesOK = asap.NewAllowedClaimValuesValidator("roles", "writer").Validate(vt) == nil

		if method == "" {
			if c.DefaultOK != expectValid {
				return fmt.Errorf("%s: DefaultValidator ok=%v want %v (%v)", name, c.DefaultOK, expectValid, c.DefaultErr)
			}
		} else {
			e = asap.NewSignatureValidator(staticFetcher{pub: ks.pub[key]}).Validate(vt)
			c.SigOK = e == nil
			c.SigErr = errString(e)
			if c.SigOK != expectValid {
				return fmt.Errorf("%s: SignatureValidator ok=%v want %v (%v)", name, c.SigOK, expectValid, c.SigErr)
			}

			jw, jerr := jws.ParseJWT([]byte(token))
			if jerr != nil {
				return fmt.Errorf("%s: jose re-parse: %w", name, jerr)
			}
			e = jw.Validate(ks.pub[key], ks.meth[method], &josejwt.Validator{EXP: time.Second, NBF: time.Second})
			c.JoseValidOK = e == nil
			c.JoseValidErr = errString(e)
			if c.JoseValidOK != c.SigOK {
				return fmt.Errorf("%s: jose Validate ok=%v but asap SignatureValidator ok=%v (jose=%v sig=%v)",
					name, c.JoseValidOK, c.SigOK, c.JoseValidErr, c.SigErr)
			}
		}
		cases = append(cases, c)
		return nil
	}

	valid := func(aud []string, iatOff, expOff time.Duration) mintOpts {
		iat := anchor.Add(iatOff)
		exp := anchor.Add(expOff)
		return mintOpts{alg: "RS256", key: "rsa2048", iss: issuer, jti: "11111111-2222-3333-4444-555555555555",
			aud: aud, iat: &iat, exp: &exp,
			extra: map[string]any{"roles": []any{"reader", "writer"}}}
	}
	mintOK := func(o mintOpts, name, method, key string, expectValid bool, note string) error {
		tok, err := mint(ks, o)
		if err != nil {
			return err
		}
		return add(name, tok, method, key, expectValid, note)
	}

	if err := mintOK(valid([]string{"aud-one"}, -5*m, 30*m), "valid_single_aud", "RS256", "rsa2048", true,
		"all required claims; exp in future, iat in past, lifetime under an hour"); err != nil {
		return nil, err
	}
	if err := mintOK(valid([]string{"aud-one", "aud-two"}, -5*m, 30*m), "valid_multi_aud", "RS256", "rsa2048", true,
		"audience array"); err != nil {
		return nil, err
	}

	// Required claim absence.
	for _, miss := range []struct {
		name string
		mod  func(*mintOpts)
	}{
		{"missing_iss", func(o *mintOpts) { o.omitIss = true }},
		{"missing_exp", func(o *mintOpts) { o.omitEXP = true }},
		{"missing_iat", func(o *mintOpts) { o.omitIAT = true }},
		{"missing_jti", func(o *mintOpts) { o.omitJTI = true }},
		{"missing_aud", func(o *mintOpts) { o.omitAud = true }},
	} {
		o := valid([]string{"aud-one"}, -5*m, 30*m)
		miss.mod(&o)
		if err := mintOK(o, miss.name, "", "", false, "required ASAP claim absent"); err != nil {
			return nil, err
		}
	}

	// ExpirationValidator boundaries: lifetime measured iat -> exp.
	for _, tc := range []struct {
		name string
		off  time.Duration
		ok   bool
	}{
		{"lifetime_exactly_one_hour", time.Hour, true},
		{"lifetime_one_second_over", time.Hour + time.Second, false},
		{"lifetime_one_second_under", time.Hour - time.Second, true},
	} {
		o := valid([]string{"aud-one"}, -10*m, -10*m+tc.off)
		if err := mintOK(o, tc.name, "", "", tc.ok, "ExpirationValidator boundary"); err != nil {
			return nil, err
		}
	}

	// Time validity as judged by SignatureValidator (1s leeway), isolated so the
	// DefaultValidator verdict stays true.
	if err := mintOK(valid([]string{"aud-one"}, -10*m, -5*m), "expired_five_minutes_ago",
		"RS256", "rsa2048", false, "exp in the past beyond leeway"); err != nil {
		return nil, err
	}
	{
		o := valid([]string{"aud-one"}, -10*m, 30*m)
		nbf := anchor.Add(5 * m)
		o.nbf = &nbf
		if err := mintOK(o, "not_before_five_minutes_ahead", "RS256", "rsa2048", false,
			"nbf in the future beyond leeway"); err != nil {
			return nil, err
		}
	}

	// Algorithms outside the ASAP allowlist. jose's parser refuses algorithms it
	// does not know at all ("no algorithm found"), so the reachable cases are
	// HS256 and none, both of which jose parses happily and asap's
	// algorithmValidator then rejects.
	{
		hs, err := mintHS256(anchor)
		if err != nil {
			return nil, err
		}
		if err := add("unsupported_algorithm_hs256", hs, "", "", false,
			"alg HS256 is not in the RS/ES/PS allowlist"); err != nil {
			return nil, err
		}
	}
	{
		none := handcraft(`{"alg":"none","typ":"JWT","kid":"svc-issuer/key1"}`,
			`{"iss":"svc-issuer","jti":"j","aud":"aud-one","iat":1,"exp":2}`)
		if err := add("unsupported_algorithm_none", none, "", "", false,
			"alg none is not in the RS/ES/PS allowlist"); err != nil {
			return nil, err
		}
	}

	// Correct claims, signature checked against the wrong key.
	{
		tok, err := mint(ks, valid([]string{"aud-one"}, -5*m, 30*m))
		if err != nil {
			return nil, err
		}
		if err := add("signed_by_wrong_key", tok, "RS256", "ec256", false,
			"signature verified against an unrelated key"); err != nil {
			return nil, err
		}
	}

	// kid formatting rules.
	for _, kidCase := range []struct {
		name string
		mod  func(*mintOpts)
		note string
	}{
		{"kid_without_issuer_prefix", func(o *mintOpts) { o.kid = "other/key" }, "kid must start with issuer/"},
		{"kid_path_traversal", func(o *mintOpts) { o.kid = issuer + "/../key" }, "kid must not contain . or .. segments"},
		{"kid_invalid_chars", func(o *mintOpts) { o.kid = issuer + "/key!" }, "kid must match ^[\\w.\\-+/]*$"},
		{"kid_missing", func(o *mintOpts) { o.omitKid = true }, "kid header absent"},
	} {
		o := valid([]string{"aud-one"}, -5*m, 30*m)
		kidCase.mod(&o)
		if err := mintOK(o, kidCase.name, "", "", false, kidCase.note); err != nil {
			return nil, err
		}
	}

	// Valid structure, tampered payload -> signature mismatch.
	{
		tok, err := mint(ks, valid([]string{"aud-one"}, -5*m, 30*m))
		if err != nil {
			return nil, err
		}
		if err := add("payload_tampered", tamperPayload(tok), "RS256", "rsa2048", false,
			"payload replaced after signing"); err != nil {
			return nil, err
		}
	}

	// The audience verdict has to discriminate, otherwise the fixture would pass
	// no matter what Claims.Audience() does.
	var anyAudienceOK, anyAudienceRejected bool
	for _, c := range cases {
		if c.AudienceOK {
			anyAudienceOK = true
		} else {
			anyAudienceRejected = true
		}
	}
	if !anyAudienceOK || !anyAudienceRejected {
		return nil, fmt.Errorf("audience verdicts do not discriminate (ok=%v rejected=%v)", anyAudienceOK, anyAudienceRejected)
	}

	sort.SliceStable(cases, func(i, j int) bool { return cases[i].Name < cases[j].Name })
	return cases, nil
}

type staticFetcher struct{ pub any }

func (f staticFetcher) Fetch(string) (any, error) { return f.pub, nil }

// hmacSecret signs the HS256 token used to exercise the algorithm allowlist. It
// is deliberately not key material for any verification the fixtures perform:
// asap rejects HS256 before it ever fetches a key.
const hmacSecret = "asap-parity-hmac-secret"

func mintHS256(anchor time.Time) (string, error) {
	claims := jws.Claims{}
	iat := anchor.Add(-5 * time.Minute)
	exp := anchor.Add(30 * time.Minute)
	claims.SetIssuer(issuer)
	claims.SetJWTID("j")
	claims.SetIssuedAt(iat)
	claims.SetExpiration(exp)
	claims.SetAudience("aud-one")
	t := jws.NewJWT(claims, josecrypto.SigningMethodHS256)
	t.(jws.JWS).Protected().Set("kid", issuer+"/key1")
	raw, err := t.Serialize([]byte(hmacSecret))
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// ------------------------------------------------------------------- helpers

func errString(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

func b64(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func b64pad(s string) string {
	return base64.URLEncoding.EncodeToString([]byte(s))
}

func handcraft(header, payload string) string {
	return b64(header) + "." + b64(payload) + ".AAAA"
}

func tamperPayload(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return token
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return token
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return token
	}
	claims["jti"] = "tampered-jti"
	out, err := json.Marshal(claims)
	if err != nil {
		return token
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(out)
	return strings.Join(parts, ".")
}

func mustMintHS256() string {
	header := b64(`{"alg":"HS256","typ":"JWT"}`)
	payload := b64(`{"iss":"svc-issuer","aud":"aud-one"}`)
	mac := hmac.New(sha256.New, []byte("public-key-bytes"))
	mac.Write([]byte(header + "." + payload))
	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func canonicalJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`null`)
	}
	return b
}

func sanitize(name string) string {
	return strings.NewReplacer(" ", "_", ".", "_", "/", "_").Replace(name)
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "paritygen:", err)
	os.Exit(1)
}
