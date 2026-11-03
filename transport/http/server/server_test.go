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

func TestShutdownEndsRequestsThatWaitUntilShutdown(t *testing.T) {
	entered := make(chan struct{})
	server, err := New(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		ctx, stop := UntilShutdown(request.Context())
		defer stop()
		close(entered)
		<-ctx.Done()
	}), ProfileOperator)
	if err != nil {
		t.Fatal(err)
	}
	bindings := serveForTest(t, server)
	go func() { _, _ = getForTest(bindings[0]) }()
	<-entered
	start := time.Now()
	if err := Shutdown(bindings); err != nil {
		t.Fatalf("Shutdown() = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Shutdown() waited %s for an open stream", elapsed)
	}
}

func TestShutdownLetsOtherRequestsFinish(t *testing.T) {
	entered, finished := make(chan struct{}), make(chan struct{})
	server, err := New(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		close(entered)
		time.Sleep(100 * time.Millisecond)
		writer.WriteHeader(http.StatusNoContent)
		close(finished)
	}), ProfileAPI)
	if err != nil {
		t.Fatal(err)
	}
	bindings := serveForTest(t, server)
	statuses := make(chan int, 1)
	go func() {
		status, _ := getForTest(bindings[0])
		statuses <- status
	}()
	<-entered
	if err := Shutdown(bindings); err != nil {
		t.Fatalf("Shutdown() = %v", err)
	}
	select {
	case <-finished:
	default:
		t.Fatal("Shutdown() returned before the request finished")
	}
	if status := <-statuses; status != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", status, http.StatusNoContent)
	}
}

func TestShutdownStopsServersAtTheSameTime(t *testing.T) {
	secondStopping := make(chan struct{})
	entered := make(chan struct{})
	first, err := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(entered)
		<-secondStopping
	}), ProfileAPI)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), ProfileAPI)
	if err != nil {
		t.Fatal(err)
	}
	second.RegisterOnShutdown(func() { close(secondStopping) })
	bindings := append(serveForTest(t, first), serveForTest(t, second)...)
	go func() { _, _ = getForTest(bindings[0]) }()
	<-entered
	start := time.Now()
	if err := Shutdown(bindings); err != nil {
		t.Fatalf("Shutdown() = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Shutdown() took %s", elapsed)
	}
}

func serveForTest(t *testing.T, server *http.Server) []Binding {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return []Binding{{Server: server, Listener: listener}}
}

func getForTest(binding Binding) (int, error) {
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+binding.Listener.Addr().String()+"/", nil)
	if err != nil {
		return 0, err
	}
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		return 0, err
	}
	defer func() { _ = response.Body.Close() }()
	return response.StatusCode, nil
}
