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
		Value: signMessage([]byte(`{"foo":"bar", "answer":42}`), secrets[0]),
	})

	writer := httptest.NewRecorder()

	values, err := sc.GetValues(req, writer, "test")
	if err != nil {
		t.Fatal(err)
	}

	if values["foo"] != "bar" {
		t.Errorf("Expected foo to be bar, got %s", values["foo"])
	}

	if values["answer"] != 42.0 {
		t.Errorf("Expected answer to be 42, got %d", values["answer"])
	}

	if len(writer.Header().Get("Set-Cookie")) != 0 {
		t.Errorf("Expected no cookie to be set")
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

	writer := httptest.NewRecorder()

	values, err := sc.GetValues(req, writer, "test")
	if err != nil {
		t.Fatal(err)
	}

	if values["foo"] != "bar" {
		t.Errorf("Expected foo to be bar, got %s", values["foo"])
	}

	// expect the cookie to be saved with the new secret
	sc = New(secrets[0])
	request := &http.Request{
		Header: http.Header{
			"Cookie": []string{writer.Header().Get("Set-Cookie")},
		},
	}

	writer = httptest.NewRecorder()
	values, err = sc.GetValues(request, writer, "test")
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

	writer = httptest.NewRecorder()
	result, err := sc.GetValues(request, writer, "test")
	if err != nil {
		t.Fatal(err)
	}

	if result["foo"] != expected["foo"] {
		t.Errorf("Expected foo to be bar, got %s", result["foo"])
	}
}

func TestSetCookieOptions(t *testing.T) {
	secrets := []string{"secret1", "secret2"}
	sc := New(secrets...)

	sc.CookieOptions = CookieOptions{
		MaxAge:   3600,
		Domain:   "example.com",
		Path:     "/path",
		HttpOnly: false,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
	}

	expected := CookieValues{
		"foo": "bar",
	}

	writer := httptest.NewRecorder()
	err := sc.SetValues(writer, "test", expected)

	if err != nil {
		t.Fatal(err)
	}

	cookie, err := http.ParseSetCookie(writer.Header().Get("Set-Cookie"))
	if err != nil {
		t.Fatal(err)
	}

	if cookie.MaxAge != 3600 {
		t.Errorf("Expected MaxAge to be 3600, got %d", cookie.MaxAge)
	}

	if cookie.Domain != "example.com" {
		t.Errorf("Expected Domain to be example.com, got %s", cookie.Domain)
	}

	if cookie.Path != "/path" {
		t.Errorf("Expected Path to be /path, got %s", cookie.Path)
	}

	if cookie.HttpOnly != false {
		t.Errorf("Expected HttpOnly to be false, got %t", cookie.HttpOnly)
	}

	if cookie.Secure != false {
		t.Errorf("Expected Secure to be false, got %t", cookie.Secure)
	}

	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("Expected SameSite to be http.SameSiteStrictMode, got %v", cookie.SameSite)
	}
}

// TODO:
// - test expected errors on no secrets
// - test expected errors on invalid digest type
// - test expected errors on invalid signature
// - test expected errors on invalid JSON
// - test to check compatibility with gleam
// - test to check compatibility with elixir-plug
