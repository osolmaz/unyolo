//go:build linux

package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/osolmaz/brokerkit/clienthttp"
)

// LocalHTTPClient returns a client for broker-local readiness checks without
// inheriting proxy settings from the service environment.
func LocalHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{Transport: transport}
}

// EndpointReadyCheck returns a readiness check over a directly dialable broker endpoint.
func EndpointReadyCheck(endpointURI, requestPath string) ReadinessCheck {
	baseURL, client, err := clienthttp.ForEndpoint(endpointURI, LocalHTTPClient())
	if err != nil || requestPath == "" || !strings.HasPrefix(requestPath, "/") {
		return func(context.Context) error { return errors.New("invalid readiness endpoint") }
	}
	return HTTPReadyCheck(strings.TrimRight(baseURL, "/")+requestPath, client)
}

// HTTPReadyCheck returns a readiness check that accepts any successful HTTP
// status. The request body is never read or included in errors.
func HTTPReadyCheck(rawURL string, client *http.Client) ReadinessCheck {
	if client == nil {
		client = http.DefaultClient
	}
	readinessClient := *client
	readinessClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return func(ctx context.Context) error {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return errors.New("invalid readiness endpoint")
		}
		response, err := readinessClient.Do(request)
		if err != nil {
			return errors.New("readiness request failed")
		}
		_ = response.Body.Close()
		if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
			return fmt.Errorf("readiness endpoint returned HTTP %d", response.StatusCode)
		}
		return nil
	}
}
