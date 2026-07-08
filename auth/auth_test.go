package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"testing"
)

func TestAuthenticateBearerAndBasic(t *testing.T) {
	authenticator, err := New(map[string]string{
		"bob":   "bob-secret-with-enough-bytes",
		"agent": "agent-secret-with-enough-bytes",
	}, Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	got, err := authenticator.AuthenticateHeader("Bearer agent-secret-with-enough-bytes")
	if err != nil || got != "agent" {
		t.Fatalf("AuthenticateHeader(Bearer) = %q, %v; want agent nil", got, err)
	}

	basic := base64.StdEncoding.EncodeToString([]byte("git:bob-secret-with-enough-bytes"))
	got, err = authenticator.AuthenticateHeader("Basic " + basic)
	if err != nil || got != "bob" {
		t.Fatalf("AuthenticateHeader(Basic) = %q, %v; want bob nil", got, err)
	}
}

func TestAuthenticateTrimsCredentialSpacing(t *testing.T) {
	authenticator, err := New(map[string]string{"bob": "bob-secret-with-enough-bytes"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := authenticator.AuthenticateHeader("Bearer   bob-secret-with-enough-bytes")
	if err != nil || got != "bob" {
		t.Fatalf("AuthenticateHeader(spaced Bearer) = %q, %v; want bob nil", got, err)
	}
	basic := base64.StdEncoding.EncodeToString([]byte("git:bob-secret-with-enough-bytes"))
	got, err = authenticator.AuthenticateHeader("Basic   " + basic)
	if err != nil || got != "bob" {
		t.Fatalf("AuthenticateHeader(spaced Basic) = %q, %v; want bob nil", got, err)
	}
}

func TestAuthenticateFailures(t *testing.T) {
	authenticator, err := New(map[string]string{"bob": "bob-secret-with-enough-bytes"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authenticator.AuthenticateHeader(""); !errors.Is(err, ErrMissing) {
		t.Fatalf("missing auth error = %v, want ErrMissing", err)
	}
	if _, err := authenticator.AuthenticateHeader("Digest value"); !errors.Is(err, ErrMissing) {
		t.Fatalf("unsupported auth error = %v, want ErrMissing", err)
	}
	if _, err := authenticator.AuthenticateHeader("Bearer wrong-secret"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid auth error = %v, want ErrInvalid", err)
	}
}

func TestAuthenticateRequest(t *testing.T) {
	authenticator, err := New(map[string]string{"bob": "bob-secret-with-enough-bytes"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)
	req.Header.Set("Authorization", "Bearer bob-secret-with-enough-bytes")
	got, err := authenticator.AuthenticateRequest(req)
	if err != nil || got != "bob" {
		t.Fatalf("AuthenticateRequest() = %q, %v; want bob nil", got, err)
	}
}

func TestNewValidatesClients(t *testing.T) {
	if _, err := New(nil, Options{}); err == nil {
		t.Fatal("New(nil) error = nil, want error")
	}
	if _, err := New(map[string]string{"": "long-enough-secret-value"}, Options{}); err == nil {
		t.Fatal("New(empty id) error = nil, want error")
	}
	if _, err := New(map[string]string{"bob": "short"}, Options{}); err == nil {
		t.Fatal("New(short secret) error = nil, want error")
	}
	if _, err := New(map[string]string{
		"bob":   "same-secret-with-enough-bytes",
		"agent": "same-secret-with-enough-bytes",
	}, Options{}); err == nil {
		t.Fatal("New(duplicate secrets) error = nil, want error")
	}
	if _, err := New(map[string]string{"bob": "short"}, Options{MinSecretBytes: 5}); err != nil {
		t.Fatalf("New(custom minimum) error = %v", err)
	}
}
