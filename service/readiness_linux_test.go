//go:build linux

package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPReadyCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	if err := HTTPReadyCheck(server.URL, server.Client())(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPReadyCheckRejectsFailureWithoutResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Error(writer, "sensitive provider response", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	err := HTTPReadyCheck(server.URL, server.Client())(context.Background())
	if err == nil || !strings.Contains(err.Error(), "503") || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("HTTPReadyCheck() error = %v", err)
	}
}
