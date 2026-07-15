package serverhttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestProfiles(t *testing.T) {
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	api, err := New(handler, ProfileAPI)
	if err != nil || api.ReadTimeout != 15*time.Second || api.WriteTimeout != 35*time.Second {
		t.Fatalf("API profile = %#v, %v", api, err)
	}
	streaming, err := New(handler, ProfileStreaming)
	if err != nil || streaming.ReadTimeout != 0 || streaming.WriteTimeout != 0 {
		t.Fatalf("streaming profile = %#v, %v", streaming, err)
	}
	operator, err := New(handler, ProfileOperator)
	if err != nil || operator.ReadTimeout != 15*time.Second || operator.WriteTimeout != 0 {
		t.Fatalf("operator profile = %#v, %v", operator, err)
	}
	if _, err := New(nil, ProfileAPI); err == nil {
		t.Fatal("New(nil) succeeded")
	}
	if _, err := New(handler, "unknown"); err == nil {
		t.Fatal("New(unknown) succeeded")
	}
}

func TestServeStopsOnContextCancellation(t *testing.T) {
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, _ := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), ProfileAPI)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, []Binding{{Server: server, Listener: listener}}) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not join shutdown")
	}
}

func TestServeRejectsInvalidBindings(t *testing.T) {
	if err := Serve(t.Context(), nil); err == nil {
		t.Fatal("Serve(nil) error = nil")
	}
	if err := Serve(t.Context(), []Binding{{}}); err == nil {
		t.Fatal("Serve(empty binding) error = nil")
	}
}

func TestServeStopsPeersWhenServerExits(t *testing.T) {
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, _ := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), ProfileAPI)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	err = Serve(t.Context(), []Binding{{Server: server, Listener: listener}})
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("Serve(closed listener) error = %v", err)
	}
}
