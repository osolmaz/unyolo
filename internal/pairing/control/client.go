// Package control talks to the local pairing service control endpoint over
// a Unix socket. It carries no secrets to the network and is only reachable
// on the loopback filesystem.
package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	pairingv1 "github.com/osolmaz/unyolo/protocol/pairing"
	"github.com/osolmaz/unyolo/transport/endpoint"
	clienthttp "github.com/osolmaz/unyolo/transport/http/client"
)

// Client is a bounded, redirect-free wrapper over the pairing control API.
type Client struct {
	baseURL string
	http    *http.Client
}

// New wires one HTTP transport for the local control endpoint.
//
// endpointURI must be a unix:// or activation:// URL. Any other scheme is
// rejected so callers cannot accidentally speak the control protocol on the
// network.
func New(endpointURI string) (*Client, error) {
	parsed, err := endpoint.Parse(endpointURI, endpoint.ParseOptions{})
	if err != nil {
		return nil, err
	}
	if parsed.Scheme() != endpoint.SchemeUnix && parsed.Scheme() != endpoint.SchemeActivation {
		return nil, errors.New("pairing control endpoint must be a local Unix socket")
	}
	baseURL, httpClient, err := clienthttp.ForEndpoint(endpointURI, nil)
	if err != nil {
		return nil, err
	}
	httpClient.Timeout = 15 * time.Second
	return &Client{baseURL: baseURL, http: httpClient}, nil
}

// InvitationOptions duplicates the wire fields for creating one invitation.
type InvitationOptions struct {
	ID            string
	Endpoint      string
	CACertificate []byte
	ServerName    string
	ExpiresAt     time.Time
	Bundle        pairingv1.Bundle
}

type createRequest struct {
	ID            string           `json:"id"`
	Endpoint      string           `json:"endpoint"`
	CACertificate string           `json:"ca_certificate"`
	ServerName    string           `json:"server_name"`
	ExpiresAt     time.Time        `json:"expires_at"`
	Bundle        pairingv1.Bundle `json:"bundle"`
}

type createResponse struct {
	Invitation string `json:"invitation"`
}

// Create requests one invitation from the pairing service.
func (client *Client) Create(ctx context.Context, options InvitationOptions) (string, error) {
	payload := createRequest{
		ID: options.ID, Endpoint: options.Endpoint,
		CACertificate: base64.RawStdEncoding.EncodeToString(options.CACertificate),
		ServerName:    options.ServerName, ExpiresAt: options.ExpiresAt.UTC(), Bundle: options.Bundle,
	}
	var result createResponse
	if err := client.do(ctx, http.MethodPost, "/v1/pairings", payload, &result); err != nil {
		return "", err
	}
	return result.Invitation, nil
}

// State reads the current pairing state via the protected control endpoint.
func (client *Client) State(ctx context.Context, id string) (pairingv1.StateResponse, error) {
	var result pairingv1.StateResponse
	if err := client.do(ctx, http.MethodGet, "/v1/pairings/"+id, nil, &result); err != nil {
		return pairingv1.StateResponse{}, err
	}
	return result, nil
}

// Activate authorizes the reviewed connection after the client reported ready.
func (client *Client) Activate(ctx context.Context, id string) (pairingv1.StateResponse, error) {
	var result pairingv1.StateResponse
	if err := client.do(ctx, http.MethodPost, "/v1/pairings/"+id+"/activate", nil, &result); err != nil {
		return pairingv1.StateResponse{}, err
	}
	return result, nil
}

// Revoke cancels a pending invitation. It returns an error if the pairing has
// already been activated; the caller must run a connection-removal plan in
// that case.
func (client *Client) Revoke(ctx context.Context, id string) error {
	return client.do(ctx, http.MethodDelete, "/v1/pairings/"+id, nil, nil)
}

func (client *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, client.baseURL+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.http.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		text, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("pairing control returned HTTP %d: %s", response.StatusCode, bytes.TrimSpace(text))
	}
	if out == nil {
		return nil
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, pairingv1.MaxMessageBytes+1))
	decoder.DisallowUnknownFields()
	return decoder.Decode(out)
}
