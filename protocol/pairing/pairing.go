// Package pairing defines the canonical remote-pairing V1 wire contract.
package pairing

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/osolmaz/unyolo/internal/strictjson"
)

const (
	APIVersion           = "unyolo.io/pairing/v1"
	InvitationPrefix     = "unyolo-pair-v1."
	MaxMessageBytes      = 1024 * 1024
	MaxBrokerConnections = 32
)

var idPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)

type Invitation struct {
	APIVersion    string    `json:"api_version"`
	Endpoint      string    `json:"endpoint"`
	PairingID     string    `json:"pairing_id"`
	Token         string    `json:"token"`
	CACertificate string    `json:"ca_certificate"`
	CAFingerprint string    `json:"ca_fingerprint"`
	ServerName    string    `json:"server_name"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type BrokerConnection struct {
	BrokerName  string `json:"broker_name"`
	ClientID    string `json:"client_id"`
	Endpoint    string `json:"endpoint"`
	GitEndpoint string `json:"git_endpoint,omitempty"`
	Secret      string `json:"shared_secret"`
	ServerName  string `json:"server_name"`
}

type Bundle struct {
	APIVersion    string             `json:"api_version"`
	PairingID     string             `json:"pairing_id"`
	ClaimSecret   string             `json:"claim_secret"`
	CACertificate string             `json:"ca_certificate"`
	Connections   []BrokerConnection `json:"connections"`
}

type StateResponse struct {
	APIVersion string `json:"api_version"`
	PairingID  string `json:"pairing_id"`
	State      string `json:"state"`
}

func EncodeInvitation(value Invitation) (string, error) {
	if err := value.Validate(); err != nil {
		return "", err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return InvitationPrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

func DecodeInvitation(encoded string) (Invitation, error) {
	if !strings.HasPrefix(encoded, InvitationPrefix) || len(encoded) > MaxMessageBytes*2 {
		return Invitation{}, errors.New("pairing invitation is invalid")
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(encoded, InvitationPrefix))
	if err != nil || len(data) > MaxMessageBytes {
		return Invitation{}, errors.New("pairing invitation is invalid")
	}
	var value Invitation
	if err := strictjson.Decode(data, &value, true); err != nil {
		return Invitation{}, errors.New("pairing invitation is invalid")
	}
	if err := value.Validate(); err != nil {
		return Invitation{}, err
	}
	return value, nil
}

func (value Invitation) Validate() error {
	if value.APIVersion != APIVersion || !validID(value.PairingID) || lenDecoded(value.Token) != 32 ||
		value.ExpiresAt.IsZero() || strings.TrimSpace(value.ServerName) == "" || strings.ContainsAny(value.ServerName, "\x00\r\n/") {
		return errors.New("pairing invitation identity is invalid")
	}
	parsed, err := url.Parse(value.Endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
		return errors.New("pairing invitation endpoint is invalid")
	}
	certificate, err := base64.RawStdEncoding.DecodeString(value.CACertificate)
	if err != nil || len(certificate) == 0 || len(certificate) > 64*1024 {
		return errors.New("pairing invitation CA certificate is invalid")
	}
	fingerprint := fmt.Sprintf("sha256:%x", sha256.Sum256(certificate))
	if value.CAFingerprint != fingerprint {
		return errors.New("pairing invitation CA fingerprint is invalid")
	}
	return nil
}

func (value Bundle) Validate() error {
	if value.APIVersion != APIVersion || !validID(value.PairingID) || lenDecoded(value.ClaimSecret) != 32 || len(value.Connections) == 0 || len(value.Connections) > MaxBrokerConnections {
		return errors.New("pairing bundle identity is invalid")
	}
	certificate, err := base64.RawStdEncoding.DecodeString(value.CACertificate)
	if err != nil || len(certificate) == 0 || len(certificate) > 64*1024 {
		return errors.New("pairing bundle CA certificate is invalid")
	}
	seen := map[string]bool{}
	for _, connection := range value.Connections {
		if !validID(connection.BrokerName) || !validID(connection.ClientID) || len(connection.Secret) < 32 || seen[connection.BrokerName] ||
			!strings.HasPrefix(connection.Endpoint, "tls://") || strings.TrimSpace(connection.ServerName) == "" {
			return errors.New("pairing bundle connection is invalid or duplicated")
		}
		seen[connection.BrokerName] = true
	}
	return nil
}

func validID(value string) bool { return len(value) <= 64 && idPattern.MatchString(value) }

func lenDecoded(value string) int {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return -1
	}
	return len(decoded)
}
