// Package serverhttp owns reviewed broker HTTP server profiles and shutdown.
package serverhttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// Profile identifies one bounded HTTP traffic shape.
type Profile string

const (
	ProfileAPI       Profile = "api"
	ProfileStreaming Profile = "streaming"
	ProfileOperator  Profile = "operator"
)

// Binding joins a configured server to an already acquired listener.
type Binding struct {
	Server   *http.Server
	Listener net.Listener
}

// New returns a server configured for one reviewed traffic profile.
func New(handler http.Handler, profile Profile) (*http.Server, error) {
	if handler == nil {
		return nil, errors.New("HTTP handler is required")
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	switch profile {
	case ProfileAPI:
		server.ReadTimeout = 15 * time.Second
		server.WriteTimeout = 35 * time.Second
	case ProfileStreaming:
		server.IdleTimeout = 2 * time.Minute
	case ProfileOperator:
		server.ReadTimeout = 15 * time.Second
		server.IdleTimeout = 90 * time.Second
	default:
		return nil, errors.New("HTTP server profile is invalid")
	}
	return server, nil
}

// Serve runs every binding under one cancellable lifecycle and joins shutdown.
func Serve(ctx context.Context, bindings []Binding) error {
	if len(bindings) == 0 {
		return errors.New("at least one HTTP listener is required")
	}
	if err := validateBindings(bindings); err != nil {
		return err
	}
	errorsChannel := serveBindings(bindings)
	select {
	case err := <-errorsChannel:
		shutdownErr := Shutdown(bindings)
		if errors.Is(err, http.ErrServerClosed) {
			return shutdownErr
		}
		return errors.Join(err, shutdownErr)
	case <-ctx.Done():
		return Shutdown(bindings)
	}
}

func validateBindings(bindings []Binding) error {
	for _, binding := range bindings {
		if binding.Server == nil || binding.Listener == nil {
			return errors.New("HTTP server and listener are required")
		}
	}
	return nil
}

func serveBindings(bindings []Binding) <-chan error {
	errorsChannel := make(chan error, len(bindings))
	for _, binding := range bindings {
		go func(value Binding) { errorsChannel <- value.Server.Serve(value.Listener) }(binding)
	}
	return errorsChannel
}

// Shutdown gracefully stops every server and closes every listener.
func Shutdown(bindings []Binding) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var result error
	for _, binding := range bindings {
		if binding.Server != nil {
			result = errors.Join(result, binding.Server.Shutdown(ctx))
		}
		if binding.Listener != nil {
			if err := binding.Listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				result = errors.Join(result, err)
			}
		}
	}
	return result
}
