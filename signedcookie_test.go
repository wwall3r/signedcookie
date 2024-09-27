package signedcookie

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetValuesMainSecret(t *testing.T) {
	secrets := []string{"secret1", "secret2"}
	sc := New(secrets...)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "test",
		Value: signMessage([]byte(`{"foo":"bar"}`), secrets[0]),
	})

	values, err := sc.GetValues(req, "test")
	if err != nil {
		t.Fatal(err)
	}

	if values["foo"] != "bar" {
		t.Errorf("Expected foo to be bar, got %s", values["foo"])
	}
}

func TestGetValuesSecondSecret(t *testing.T) {
	secrets := []string{"secret1", "secret2"}
	sc := New(secrets...)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "test",
		Value: signMessage([]byte(`{"foo":"bar"}`), secrets[1]),
	})

	values, err := sc.GetValues(req, "test")
	if err != nil {
		t.Fatal(err)
	}

	if values["foo"] != "bar" {
		t.Errorf("Expected foo to be bar, got %s", values["foo"])
	}
}

func TestSetValues(t *testing.T) {
	secrets := []string{"secret1", "secret2"}
	sc := New(secrets...)

	expected := CookieValues{
		"foo": "bar",
	}

	writer := httptest.NewRecorder()
	err := sc.SetValues(writer, "test", expected)

	if err != nil {
		t.Fatal(err)
	}

	request := &http.Request{
		Header: http.Header{
			"Cookie": []string{writer.Header().Get("Set-Cookie")},
		},
	}

	result, err := sc.GetValues(request, "test")
	if err != nil {
		t.Fatal(err)
	}

	if result["foo"] != expected["foo"] {
		t.Errorf("Expected foo to be bar, got %s", result["foo"])
	}
}

// TODO:
// - test to check that a cookie with an older secret is saved with the new secret,
//   which will probably require sending the response writer to GetValues
// - test for CookieOptions
// - test expected errors on no secrets
// - test expected errors on invalid digest type
// - test expected errors on invalid signature
// - test expected errors on invalid JSON
// - test to check compatibility with gleam
// - test to check compatibility with elixir-plug
