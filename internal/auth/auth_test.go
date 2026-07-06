package auth

import (
	"encoding/base64"
	"errors"
	"testing"
)

func TestAuthenticateBearerAndBasic(t *testing.T) {
	authenticator := New(map[string]string{
		"agent": "abcdefghijklmnopqrstuvwxyz123456",
	})
	tests := []struct {
		name   string
		header string
	}{
		{name: "bearer", header: "Bearer abcdefghijklmnopqrstuvwxyz123456"},
		{name: "basic", header: "Basic " + base64.StdEncoding.EncodeToString([]byte("ignored:abcdefghijklmnopqrstuvwxyz123456"))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, err := authenticator.Authenticate(tc.header)
			if err != nil {
				t.Fatalf("Authenticate() error = %v", err)
			}
			if client != "agent" {
				t.Fatalf("client = %q, want agent", client)
			}
		})
	}
}

func TestAuthenticateFailures(t *testing.T) {
	authenticator := New(map[string]string{"agent": "abcdefghijklmnopqrstuvwxyz123456"})
	tests := []struct {
		name string
		h    string
		want error
	}{
		{name: "missing", want: ErrMissing},
		{name: "wrong scheme", h: "Digest abc", want: ErrMissing},
		{name: "bad basic", h: "Basic !!!!", want: ErrMissing},
		{name: "wrong secret", h: "Bearer abcdefghijklmnopqrstuvwxyz123457", want: ErrInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := authenticator.Authenticate(tc.h)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Authenticate() error = %v, want %v", err, tc.want)
			}
		})
	}
}
