// Package intent defines the closed, nonsecret guided-setup intent.
package intent

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/osolmaz/unyolo/internal/strictjson"
)

const (
	APIVersion      = "unyolo.io/setup-intent/v1"
	MaxDocumentSize = 1024 * 1024
	MaxProviders    = 32
	MaxIntegrations = 32
)

var namePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)

type Goal string

const (
	GoalCommandOnly       Goal = "command_only"
	GoalCredentialService Goal = "credential_service"
	GoalAgentConnection   Goal = "agent_connection"
	GoalCompleteLocal     Goal = "complete_local"
)

type ServiceLocation string

const (
	ServiceNative ServiceLocation = "native"
	ServiceDocker ServiceLocation = "docker"
)

type AgentLocation string

const (
	AgentLocalAccount AgentLocation = "local_account"
	AgentContainer    AgentLocation = "container"
	AgentRemote       AgentLocation = "remote"
)

type AccountMode string

const (
	AccountCurrent  AccountMode = "current"
	AccountExisting AccountMode = "existing"
	AccountManaged  AccountMode = "managed"
)

type Transport string

const (
	TransportLocalSocket Transport = "local_socket"
	TransportTLS         Transport = "tls"
)

type CredentialService struct {
	Location  ServiceLocation `json:"location"`
	Providers []string        `json:"providers"`
}

type Account struct {
	Mode AccountMode `json:"mode"`
	Name string      `json:"name,omitempty"`
}

type Container struct {
	ProjectDirectory string `json:"project_directory"`
	Service          string `json:"service"`
}

type Agent struct {
	Location       AgentLocation `json:"location"`
	ConnectionName string        `json:"connection_name"`
	Account        *Account      `json:"account,omitempty"`
	Container      *Container    `json:"container,omitempty"`
}

type Connection struct {
	Transport      Transport `json:"transport"`
	RemoteEndpoint string    `json:"remote_endpoint,omitempty"`
	ServerName     string    `json:"server_name,omitempty"`
}

// Intent contains user choices only. Credential values and pairing invitations are forbidden.
type Intent struct {
	APIVersion        string             `json:"api_version"`
	Goal              Goal               `json:"goal"`
	CredentialService *CredentialService `json:"credential_service,omitempty"`
	Agent             *Agent             `json:"agent,omitempty"`
	Connection        *Connection        `json:"connection,omitempty"`
	Integrations      []string           `json:"integrations,omitempty"`
}

func Decode(data []byte) (Intent, error) {
	if len(data) == 0 || len(data) > MaxDocumentSize {
		return Intent{}, errors.New("setup intent size is invalid")
	}
	var value Intent
	if err := strictjson.Decode(data, &value, true); err != nil {
		return Intent{}, fmt.Errorf("decode setup intent: %w", err)
	}
	if err := value.Validate(); err != nil {
		return Intent{}, err
	}
	return value, nil
}

// Validate enforces the closed cross-field contract.
func (value Intent) Validate() error {
	if value.APIVersion != APIVersion || !slices.Contains([]Goal{GoalCommandOnly, GoalCredentialService, GoalAgentConnection, GoalCompleteLocal}, value.Goal) {
		return errors.New("setup intent identity is invalid")
	}
	needsService := value.Goal == GoalCredentialService || value.Goal == GoalCompleteLocal
	needsAgent := value.Goal == GoalAgentConnection || value.Goal == GoalCompleteLocal
	if needsService != (value.CredentialService != nil) || needsAgent != (value.Agent != nil && value.Connection != nil) {
		return errors.New("setup intent fields do not match the selected goal")
	}
	if value.Goal == GoalCommandOnly && len(value.Integrations) != 0 {
		return errors.New("command-only setup cannot configure integrations")
	}
	if value.CredentialService != nil {
		if !slices.Contains([]ServiceLocation{ServiceNative, ServiceDocker}, value.CredentialService.Location) ||
			len(value.CredentialService.Providers) == 0 || len(value.CredentialService.Providers) > MaxProviders ||
			!uniqueNames(value.CredentialService.Providers) {
			return errors.New("credential-service selection is invalid")
		}
	}
	if value.Agent != nil {
		if err := value.Agent.validate(); err != nil {
			return err
		}
	}
	if value.Connection != nil {
		if err := value.Connection.validate(); err != nil {
			return err
		}
	}
	if len(value.Integrations) > MaxIntegrations || !uniqueNames(value.Integrations) {
		return errors.New("integration selection is invalid")
	}
	return nil
}

func (value Agent) validate() error {
	if !slices.Contains([]AgentLocation{AgentLocalAccount, AgentContainer, AgentRemote}, value.Location) || !validName(value.ConnectionName) {
		return errors.New("agent selection is invalid")
	}
	switch value.Location {
	case AgentLocalAccount:
		if value.Account == nil || value.Container != nil {
			return errors.New("local agent requires one account selection")
		}
		if !slices.Contains([]AccountMode{AccountCurrent, AccountExisting, AccountManaged}, value.Account.Mode) {
			return errors.New("agent account mode is invalid")
		}
		if value.Account.Mode == AccountCurrent && value.Account.Name != "" {
			return errors.New("current account must not override its name")
		}
		if value.Account.Mode != AccountCurrent && !validName(value.Account.Name) {
			return errors.New("existing or managed account name is invalid")
		}
	case AgentContainer:
		if value.Account != nil || value.Container == nil || !filepath.IsAbs(value.Container.ProjectDirectory) ||
			filepath.Clean(value.Container.ProjectDirectory) != value.Container.ProjectDirectory || !validName(value.Container.Service) {
			return errors.New("container agent selection is invalid")
		}
	case AgentRemote:
		if value.Account != nil || value.Container != nil {
			return errors.New("remote agent cannot contain local target fields")
		}
	}
	return nil
}

func (value Connection) validate() error {
	if !slices.Contains([]Transport{TransportLocalSocket, TransportTLS}, value.Transport) {
		return errors.New("connection transport is invalid")
	}
	if value.Transport == TransportLocalSocket {
		if value.RemoteEndpoint != "" || value.ServerName != "" {
			return errors.New("local connection cannot contain network fields")
		}
		return nil
	}
	parsed, err := url.Parse(value.RemoteEndpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
		return errors.New("remote endpoint must be an absolute HTTPS origin")
	}
	if strings.TrimSpace(value.ServerName) == "" || strings.ContainsAny(value.ServerName, "\x00\r\n/") {
		return errors.New("remote server name is invalid")
	}
	return nil
}

func uniqueNames(values []string) bool {
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if !validName(value) || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func validName(value string) bool { return len(value) <= 64 && namePattern.MatchString(value) }
