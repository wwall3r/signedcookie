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

type CookieValues = map[string]string

type CookieOptions struct {
	MaxAge   int
	Domain   string
	Path     string
	HttpOnly bool
	Secure   bool
}

type SignedCookie struct {
	secrets       []string
	CookieOptions CookieOptions
}

var defaultCookieOptions = CookieOptions{
	MaxAge:   86400,
	Domain:   "",
	Path:     "/",
	HttpOnly: true,
	Secure:   true,
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
		},
	}
}

func (sc *SignedCookie) GetValues(req *http.Request, name string) (CookieValues, error) {
	cookie, err := req.Cookie(name)
	if err != nil {
		return nil, err
	}

	for _, secret := range sc.secrets {
		value, err := verifySignedMessage(cookie.Value, secret)
		if err != nil {
			continue
		}

		values := make(CookieValues)
		err = json.Unmarshal(value, &values)
		if err != nil {
			return nil, err
		}

		return values, nil
	}

	return nil, fmt.Errorf("No secret could verify the cookie")
}

func (sc *SignedCookie) SetValues(writer http.ResponseWriter, name string, values CookieValues) error {
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
	}

	http.SetCookie(writer, cookie)

	return nil
}

func verifySignedMessage(signedMessage, secret string) ([]byte, error) {
	parts := strings.Split(signedMessage, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("Invalid signed message")
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

	text := digestStr + "." + string(payload)

	challenge := hmac.New(sha256.New, []byte(secret))
	challenge.Write([]byte(text))

	if !hmac.Equal(challenge.Sum(nil), signature) {
		return nil, fmt.Errorf("Invalid signature")
	}

	return payload, nil
}

func signMessage(message []byte, secret string) string {
	digestType := "HS256"
	text := digestType + "." + string(message)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(text))
	signature := mac.Sum(nil)

	return fmt.Sprintf("%s.%s.%s",
		base64.StdEncoding.EncodeToString([]byte(digestType)),
		base64.StdEncoding.EncodeToString(message),
		base64.StdEncoding.EncodeToString(signature),
	)
}
