package security

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestTokenAuthAllowsValidBearerToken(t *testing.T) {
	t.Parallel()
	auth, err := NewTokenAuthForClient("expected-shared-secret", "bob")
	if err != nil {
		t.Fatalf("NewTokenAuthForClient() error = %v", err)
	}
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
	request.Header.Set(echo.HeaderAuthorization, "Bearer expected-shared-secret")
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
	auth, err := NewTokenAuth("expected-shared-secret")
	if err != nil {
		t.Fatalf("NewTokenAuth() error = %v", err)
	}
	called := false
	handler := auth.Middleware(func(c echo.Context) error {
		called = true
		return c.NoContent(http.StatusNoContent)
	})
	e := echo.New()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	request.Header.Set(echo.HeaderAuthorization, "Basic "+base64.StdEncoding.EncodeToString([]byte("git:expected-shared-secret")))
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
	auth, err := NewTokenAuth("expected-shared-secret")
	if err != nil {
		t.Fatalf("NewTokenAuth() error = %v", err)
	}
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

func TestNewTokenAuthRejectsEmptyToken(t *testing.T) {
	t.Parallel()
	if _, err := NewTokenAuth(" "); err == nil {
		t.Fatal("NewTokenAuth() error = nil, want empty token error")
	}
}

func TestNewTokenAuthForClientRejectsEmptyClient(t *testing.T) {
	t.Parallel()
	if _, err := NewTokenAuthForClient("expected", " "); err == nil {
		t.Fatal("NewTokenAuthForClient() error = nil, want empty client error")
	}
}
