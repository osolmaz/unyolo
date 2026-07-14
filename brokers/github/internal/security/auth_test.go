package security

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	bkauth "github.com/osolmaz/brokerkit/auth"
)

const expectedSecret = "expected-shared-secret-1234567890"

func TestTokenAuthAllowsValidBearerToken(t *testing.T) {
	t.Parallel()
	auth := testTokenAuth(t, "bob")
	called := false
	handler := auth.Middleware(func(c echo.Context) error {
		called = true
		if ClientFromContext(c) != "bob" {
			t.Fatalf("ClientFromContext() = %q, want bob", ClientFromContext(c))
		}
		return c.NoContent(http.StatusNoContent)
	})
	e := echo.New()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	request.Header.Set(echo.HeaderAuthorization, "Bearer "+expectedSecret)
	response := httptest.NewRecorder()
	if err := handler(e.NewContext(request, response)); err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if !called || response.Code != http.StatusNoContent {
		t.Fatalf("called = %t status = %d, want success", called, response.Code)
	}
}

func TestTokenAuthAllowsValidBasicPassword(t *testing.T) {
	t.Parallel()
	auth := testTokenAuth(t, "default")
	called := false
	handler := auth.Middleware(func(c echo.Context) error {
		called = true
		return c.NoContent(http.StatusNoContent)
	})
	e := echo.New()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	request.Header.Set(echo.HeaderAuthorization, "Basic "+base64.StdEncoding.EncodeToString([]byte("git:"+expectedSecret)))
	response := httptest.NewRecorder()
	if err := handler(e.NewContext(request, response)); err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if !called || response.Code != http.StatusNoContent {
		t.Fatalf("called = %t status = %d, want success", called, response.Code)
	}
}

func TestTokenAuthRejectsMissingAndInvalidBearerToken(t *testing.T) {
	t.Parallel()
	auth := testTokenAuth(t, "default")
	handler := auth.Middleware(func(c echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	})
	e := echo.New()
	for _, header := range []string{"", "Bearer wrong"} {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
		request.Header.Set(echo.HeaderAuthorization, header)
		response := httptest.NewRecorder()
		if err := handler(e.NewContext(request, response)); err == nil {
			t.Fatalf("handler() error = nil for header %q", header)
		}
	}
}

func TestFromAuthenticatorRejectsNil(t *testing.T) {
	t.Parallel()
	if _, err := FromAuthenticator(nil); err == nil {
		t.Fatal("FromAuthenticator() error = nil, want nil authenticator error")
	}
}

func testTokenAuth(t *testing.T, client string) TokenAuth {
	t.Helper()
	authenticator, err := bkauth.New(map[string]string{client: expectedSecret}, bkauth.Options{})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := FromAuthenticator(authenticator)
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}
