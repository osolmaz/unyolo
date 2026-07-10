package operatorauth

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthenticatorSeparatesOperatorAndClientCredentials(t *testing.T) {
	const operatorSecret = "operator-secret-with-enough-entropy"
	const clientSecret = "client-secret-with-enough-entropy"
	if _, err := New(map[string]string{"onur": clientSecret}, Options{ClientSecrets: map[string]string{"bob": clientSecret}}); err == nil {
		t.Fatal("New() accepted a reused client secret")
	}
	authenticator, err := New(map[string]string{"onur": operatorSecret}, Options{ClientSecrets: map[string]string{"bob": clientSecret}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(t.Context(), "GET", "/api/grants", nil)
	if _, err := authenticator.AuthenticateRequest(request); !errors.Is(err, ErrMissing) {
		t.Fatalf("missing auth error = %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+clientSecret)
	if _, err := authenticator.AuthenticateRequest(request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("client auth error = %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+operatorSecret)
	identity, err := authenticator.AuthenticateRequest(request)
	if err != nil || identity != "onur" {
		t.Fatalf("AuthenticateRequest() = %q, %v", identity, err)
	}
}

func TestAuthenticatorRejectsWeakAndDuplicateSecrets(t *testing.T) {
	if _, err := New(map[string]string{"onur": "short"}, Options{}); err == nil {
		t.Fatal("New() accepted a weak secret")
	}
	secret := strings.Repeat("x", 32)
	if _, err := New(map[string]string{"onur": secret, "admin": secret}, Options{}); err == nil {
		t.Fatal("New() accepted duplicate operator secrets")
	}
}
