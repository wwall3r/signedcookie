/*
This implements signed cookies in the same way as [gleam](https://github.com/gleam-lang/crypto/blob/v1.3.0/src/gleam/crypto.gleam#L75)
and elixir-plug in order to be easily compatible with those libraries.

Additionally, the payload of the cookie is JSON, allowing for multiple values to
be stored in a single cookie in a format easily read by other languages.
*/
package signedcookie

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type CookieValues = map[string]interface{}

type CookieOptions struct {
	MaxAge   int
	Domain   string
	Path     string
	HttpOnly bool
	Secure   bool
	SameSite http.SameSite
}

type SignedCookie struct {
	secrets       []string
	CookieOptions CookieOptions
}

type CookieModifier func(cookie *http.Cookie)

var defaultCookieOptions = CookieOptions{
	MaxAge:   86400,
	Domain:   "",
	Path:     "/",
	HttpOnly: true,
	Secure:   true,
	SameSite: http.SameSiteLaxMode,
}

// Returns a new SignedCookie with the given secrets. The first secret should be the
// current key, and any others should be old keys for key rotation.
func New(secrets ...string) SignedCookie {
	return SignedCookie{
		secrets: secrets,
		CookieOptions: CookieOptions{
			MaxAge:   defaultCookieOptions.MaxAge,
			Domain:   defaultCookieOptions.Domain,
			Path:     defaultCookieOptions.Path,
			HttpOnly: defaultCookieOptions.HttpOnly,
			Secure:   defaultCookieOptions.Secure,
			SameSite: defaultCookieOptions.SameSite,
		},
	}
}

func (sc *SignedCookie) GetValues(req *http.Request, writer http.ResponseWriter, name string, modifiers ...CookieModifier) (CookieValues, error) {
	values := make(CookieValues)
	cookie, err := req.Cookie(name)
	if err != nil {
		// no cookie found, so return empty values
		return values, nil
	}

	for i, secret := range sc.secrets {
		value, err := verifySignedMessage(cookie.Value, secret)
		if err != nil {
			continue
		}

		err = json.Unmarshal(value, &values)
		if err != nil {
			return values, err
		}

		if i > 0 {
			sc.SetValues(writer, name, values, modifiers...)
		}

		return values, nil
	}

	return values, fmt.Errorf("No secret could verify the cookie")
}

func (sc *SignedCookie) SetValues(writer http.ResponseWriter, name string, values CookieValues, modifiers ...CookieModifier) error {
	payload, err := json.Marshal(values)
	if err != nil {
		return err
	}

	cookie := &http.Cookie{
		Name:     name,
		Value:    signMessage(payload, sc.secrets[0]),
		MaxAge:   sc.CookieOptions.MaxAge,
		Domain:   sc.CookieOptions.Domain,
		Path:     sc.CookieOptions.Path,
		HttpOnly: sc.CookieOptions.HttpOnly,
		Secure:   sc.CookieOptions.Secure,
		SameSite: sc.CookieOptions.SameSite,
	}

	for _, modifier := range modifiers {
		modifier(cookie)
	}

	http.SetCookie(writer, cookie)

	return nil
}

func (sc *SignedCookie) RemoveValues(writer http.ResponseWriter, name string) error {
	return sc.SetValues(writer, name, nil, removeModifier)
}

func removeModifier(cookie *http.Cookie) {
	cookie.MaxAge = -1
}

func verifySignedMessage(signedMessage, secret string) ([]byte, error) {
	parts := strings.Split(signedMessage, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("Invalid signed message")
	}

	text := parts[0] + "." + parts[1]

	for i := range parts {
		parts[i] = fromFileSafeAlphabet(parts[i])
	}

	digestType, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}

	payload, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	signature, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}

	digestStr := string(digestType)
	if digestStr != "HS256" {
		return nil, fmt.Errorf("Unsupported digest type: %s", digestStr)
	}

	challenge := hmac.New(sha256.New, []byte(secret))
	challenge.Write([]byte(text))

	if !hmac.Equal(challenge.Sum(nil), signature) {
		return nil, fmt.Errorf("Invalid signature")
	}

	return []byte(fromFileSafeAlphabet(string(payload))), nil
}

func signMessage(message []byte, secret string) string {
	digestType := "HS256"

	protected := base64.StdEncoding.EncodeToString([]byte(digestType))
	protected = toFileSafeAlphabet(protected)

	payload := base64.StdEncoding.EncodeToString(message)
	payload = toFileSafeAlphabet(payload) // TODO: this is probably not necessary

	text := protected + "." + payload

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(text))
	signature := mac.Sum(nil)

	signatureStr := base64.StdEncoding.EncodeToString(signature)
	signatureStr = toFileSafeAlphabet(signatureStr)

	return fmt.Sprintf("%s.%s.%s",
		protected,
		payload,
		signatureStr,
	)
}

func toFileSafeAlphabet(str string) string {
	str = strings.ReplaceAll(str, "+", "-")
	str = strings.ReplaceAll(str, "/", "_")
	return str
}

func fromFileSafeAlphabet(str string) string {
	str = strings.ReplaceAll(str, "-", "+")
	str = strings.ReplaceAll(str, "_", "/")
	return str
}
