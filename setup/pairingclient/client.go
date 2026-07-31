// Package pairingclient claims remote invitations and publishes native client files atomically.
package pairingclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	clientconfig "github.com/osolmaz/unyolo/internal/config/client"
	"github.com/osolmaz/unyolo/internal/storage/files"
	"github.com/osolmaz/unyolo/internal/strictjson"
	pairingv1 "github.com/osolmaz/unyolo/protocol/pairing"
)

type Result struct {
	Invitation pairingv1.Invitation
	Bundle     pairingv1.Bundle
	CAPath     string
}

type backup struct {
	path   string
	data   []byte
	exists bool
}

func Claim(ctx context.Context, encoded, home string) (Result, error) {
	invitation, err := pairingv1.DecodeInvitation(encoded)
	if err != nil {
		return Result{}, err
	}
	if !invitation.ExpiresAt.After(time.Now()) {
		return Result{}, errors.New("pairing invitation has expired")
	}
	client, err := invitationClient(invitation)
	if err != nil {
		return Result{}, err
	}
	bundle, err := claimBundle(ctx, client, invitation)
	if err != nil {
		return Result{}, err
	}
	if bundle.PairingID != invitation.PairingID || bundle.CACertificate != invitation.CACertificate {
		return Result{}, errors.New("pairing bundle does not match the invitation")
	}
	caPath, backups, err := publish(home, bundle)
	if err != nil {
		return Result{}, err
	}
	if err := transition(ctx, client, invitation.Endpoint, invitation.PairingID, bundle.ClaimSecret, "ready"); err != nil {
		return Result{}, errors.Join(err, restore(backups))
	}
	return Result{Invitation: invitation, Bundle: bundle, CAPath: caPath}, nil
}

func WaitForActive(ctx context.Context, result Result) error {
	client, err := invitationClient(result.Invitation)
	if err != nil {
		return err
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		state, requestErr := status(ctx, client, result.Invitation.Endpoint, result.Invitation.PairingID, result.Bundle.ClaimSecret)
		if requestErr == nil && state == "active" {
			return nil
		}
		if requestErr == nil && (state == "expired" || state == "revoked") {
			return errors.New("pairing was cancelled before activation")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func MarkVerified(ctx context.Context, result Result) error {
	client, err := invitationClient(result.Invitation)
	if err != nil {
		return err
	}
	return transition(ctx, client, result.Invitation.Endpoint, result.Invitation.PairingID, result.Bundle.ClaimSecret, "verified")
}

func invitationClient(invitation pairingv1.Invitation) (*http.Client, error) {
	certificate, err := base64.RawStdEncoding.DecodeString(invitation.CACertificate)
	if err != nil {
		return nil, errors.New("pairing invitation CA is invalid")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		return nil, errors.New("pairing invitation CA is invalid")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: invitation.ServerName}
	return &http.Client{Transport: transport, Timeout: 35 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}, nil
}

func claimBundle(ctx context.Context, client *http.Client, invitation pairingv1.Invitation) (pairingv1.Bundle, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, invitation.Endpoint+"/v1/pairings/"+invitation.PairingID+"/claim", http.NoBody)
	if err != nil {
		return pairingv1.Bundle{}, err
	}
	request.Header.Set("Authorization", "Bearer "+invitation.Token)
	response, err := client.Do(request)
	if err != nil {
		return pairingv1.Bundle{}, fmt.Errorf("claim pairing invitation: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, pairingv1.MaxMessageBytes+1))
	if err != nil || len(data) > pairingv1.MaxMessageBytes || response.StatusCode != http.StatusOK {
		return pairingv1.Bundle{}, fmt.Errorf("pairing claim returned HTTP %d", response.StatusCode)
	}
	var bundle pairingv1.Bundle
	if err := strictjson.Decode(data, &bundle, true); err != nil || bundle.Validate() != nil {
		return pairingv1.Bundle{}, errors.New("pairing service returned an invalid bundle")
	}
	return bundle, nil
}

func transition(ctx context.Context, client *http.Client, endpoint, id, secret, action string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/v1/pairings/"+id+"/"+action, http.NoBody)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+secret)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("pairing %s returned HTTP %d", action, response.StatusCode)
	}
	return nil
}

func status(ctx context.Context, client *http.Client, endpoint, id, secret string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/pairings/"+id, http.NoBody)
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", "Bearer "+secret)
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("pairing status returned HTTP %d", response.StatusCode)
	}
	var value pairingv1.StateResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, pairingv1.MaxMessageBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil || value.APIVersion != pairingv1.APIVersion || value.PairingID != id {
		return "", errors.New("pairing status response is invalid")
	}
	return value.State, nil
}

func publish(home string, bundle pairingv1.Bundle) (string, []backup, error) {
	if !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return "", nil, errors.New("pairing client home must be absolute and clean")
	}
	certificate, err := base64.RawStdEncoding.DecodeString(bundle.CACertificate)
	if err != nil {
		return "", nil, errors.New("pairing bundle CA is invalid")
	}
	caPath := filepath.Join(home, ".config", "unyolo", "connections", bundle.PairingID, "ca.pem")
	paths := []string{caPath}
	for _, connection := range bundle.Connections {
		path, pathErr := clientconfig.Path(home, connection.BrokerName)
		if pathErr != nil {
			return "", nil, pathErr
		}
		paths = append(paths, path)
	}
	backups, err := capture(paths)
	if err != nil {
		return "", nil, err
	}
	if err := store.WriteFileAtomic(caPath, certificate, 0o600); err != nil {
		return "", nil, err
	}
	for _, connection := range bundle.Connections {
		_, err = clientconfig.Write(clientconfig.Config{
			BrokerName: connection.BrokerName, EnvPrefix: envPrefix(connection.BrokerName), ClientID: connection.ClientID,
			Endpoint: connection.Endpoint, GitEndpoint: connection.GitEndpoint, Secret: connection.Secret,
			CAFile: caPath, ServerName: connection.ServerName, HomeDir: home,
		})
		if err != nil {
			return "", nil, errors.Join(err, restore(backups))
		}
	}
	return caPath, backups, nil
}

func capture(paths []string) ([]backup, error) {
	result := make([]backup, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path) // #nosec G304 -- generated paths below the selected home.
		if errors.Is(err, os.ErrNotExist) {
			result = append(result, backup{path: path})
			continue
		}
		if err != nil {
			return nil, err
		}
		result = append(result, backup{path: path, data: append([]byte(nil), data...), exists: true})
	}
	return result, nil
}

func restore(values []backup) error {
	var failures []error
	for _, value := range values {
		if value.exists {
			failures = append(failures, store.WriteFileAtomic(value.path, bytes.Clone(value.data), 0o600))
		} else if err := os.Remove(value.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func envPrefix(broker string) string {
	return strings.ToUpper(strings.ReplaceAll(broker, "-", "_"))
}
