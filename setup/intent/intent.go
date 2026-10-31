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
	GoalCredentialService Goal = "credential_service" // #nosec G101 -- public setup goal name, not a credential.
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
	AgentSandbox      AgentLocation = "sandbox"
)

// SandboxRuntime names the runtime of a sandbox agent.
type SandboxRuntime string

// SandboxOpenShell is an OpenShell sandbox on this computer.
const SandboxOpenShell SandboxRuntime = "openshell"

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
	// TransportSandbox reaches a broker's sandbox listener through the
	// sandbox runtime. The broker and the runtime adapter choose the address.
	TransportSandbox Transport = "sandbox"
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

// Sandbox is the sandbox that runs an agent. The name may stay empty in a
// draft until the user enters it.
type Sandbox struct {
	Runtime SandboxRuntime `json:"runtime"`
	Name    string         `json:"name,omitempty"`
}

type Agent struct {
	Location       AgentLocation `json:"location"`
	ConnectionName string        `json:"connection_name"`
	Account        *Account      `json:"account,omitempty"`
	Container      *Container    `json:"container,omitempty"`
	Sandbox        *Sandbox      `json:"sandbox,omitempty"`
}

// Telegram is the choice to send approval requests to one Telegram chat. The
// bot token is a credential and is collected later, never in the intent.
type Telegram struct {
	ChatID int64 `json:"chat_id"`
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
	Telegram          *Telegram          `json:"telegram,omitempty"`
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

// Validate enforces the complete closed cross-field contract.
func (value Intent) Validate() error {
	if err := value.ValidatePartial(); err != nil {
		return err
	}
	if value.Goal == "" {
		return errors.New("setup goal is required")
	}
	needsService := value.Goal == GoalCredentialService || value.Goal == GoalCompleteLocal
	needsAgent := value.Goal == GoalAgentConnection || value.Goal == GoalCompleteLocal
	if needsService != (value.CredentialService != nil) || needsAgent != (value.Agent != nil && value.Connection != nil) {
		return errors.New("setup intent fields do not match the selected goal")
	}
	if value.CredentialService != nil && len(value.CredentialService.Providers) == 0 {
		return errors.New("credential-service selection is incomplete")
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
	if value.Agent != nil && value.Connection != nil && (value.Agent.Location == AgentSandbox) != (value.Connection.Transport == TransportSandbox) {
		return errors.New("a sandbox agent and only a sandbox agent uses the sandbox transport")
	}
	return nil
}

// ValidatePartial validates a resumable draft without requiring later answers.
func (value Intent) ValidatePartial() error {
	if value.APIVersion != APIVersion || value.Goal != "" && !slices.Contains([]Goal{GoalCommandOnly, GoalCredentialService, GoalAgentConnection, GoalCompleteLocal}, value.Goal) {
		return errors.New("setup intent identity is invalid")
	}
	if value.Goal == GoalCommandOnly && (value.CredentialService != nil || value.Agent != nil || value.Connection != nil || value.Telegram != nil || len(value.Integrations) != 0) {
		return errors.New("command-only setup cannot contain host choices")
	}
	if value.Telegram != nil && (value.Telegram.ChatID == 0 || value.CredentialService == nil || value.CredentialService.Location != ServiceNative) {
		return errors.New("telegram approvals require a chat and native credential services")
	}
	if value.CredentialService != nil {
		if !slices.Contains([]ServiceLocation{ServiceNative, ServiceDocker}, value.CredentialService.Location) ||
			len(value.CredentialService.Providers) > MaxProviders ||
			len(value.CredentialService.Providers) > 0 && !uniqueNames(value.CredentialService.Providers) {
			return errors.New("credential-service selection is invalid")
		}
	}
	if value.Agent != nil {
		if err := value.Agent.validatePartial(); err != nil {
			return err
		}
	}
	if value.Connection != nil {
		if err := value.Connection.validatePartial(); err != nil {
			return err
		}
	}
	if len(value.Integrations) > MaxIntegrations || !uniqueNames(value.Integrations) {
		return errors.New("integration selection is invalid")
	}
	return nil
}

func (value Agent) validatePartial() error {
	if !slices.Contains([]AgentLocation{AgentLocalAccount, AgentContainer, AgentRemote, AgentSandbox}, value.Location) ||
		value.ConnectionName != "" && !validName(value.ConnectionName) {
		return errors.New("agent selection is invalid")
	}
	if (value.Location == AgentSandbox) != (value.Sandbox != nil) {
		return errors.New("only a sandbox agent names a sandbox")
	}
	switch value.Location {
	case AgentLocalAccount:
		if value.Account == nil || value.Container != nil || !slices.Contains([]AccountMode{AccountCurrent, AccountExisting, AccountManaged}, value.Account.Mode) {
			return errors.New("local agent requires one account selection")
		}
		if value.Account.Mode == AccountCurrent && value.Account.Name != "" ||
			value.Account.Mode != AccountCurrent && value.Account.Name != "" && !validName(value.Account.Name) {
			return errors.New("agent account selection is invalid")
		}
	case AgentContainer:
		if value.Account != nil {
			return errors.New("container agent cannot contain an account")
		}
		if value.Container != nil && (value.Container.ProjectDirectory != "" && (!filepath.IsAbs(value.Container.ProjectDirectory) || filepath.Clean(value.Container.ProjectDirectory) != value.Container.ProjectDirectory) ||
			value.Container.Service != "" && !validName(value.Container.Service)) {
			return errors.New("container agent selection is invalid")
		}
	case AgentRemote:
		if value.Account != nil || value.Container != nil {
			return errors.New("remote agent cannot contain local target fields")
		}
	case AgentSandbox:
		if value.Account != nil || value.Container != nil || value.Sandbox.Runtime != SandboxOpenShell ||
			value.Sandbox.Name != "" && !validName(value.Sandbox.Name) {
			return errors.New("sandbox agent selection is invalid")
		}
	}
	return nil
}

func (value Agent) validate() error {
	if !slices.Contains([]AgentLocation{AgentLocalAccount, AgentContainer, AgentRemote, AgentSandbox}, value.Location) || !validName(value.ConnectionName) {
		return errors.New("agent selection is invalid")
	}
	if (value.Location == AgentSandbox) != (value.Sandbox != nil) {
		return errors.New("only a sandbox agent names a sandbox")
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
	case AgentSandbox:
		if value.Account != nil || value.Container != nil || value.Sandbox.Runtime != SandboxOpenShell || !validName(value.Sandbox.Name) {
			return errors.New("sandbox agent selection is invalid")
		}
	}
	return nil
}

func (value Connection) validatePartial() error {
	if !slices.Contains([]Transport{TransportLocalSocket, TransportTLS, TransportSandbox}, value.Transport) {
		return errors.New("connection transport is invalid")
	}
	if value.Transport == TransportLocalSocket || value.Transport == TransportSandbox {
		if value.RemoteEndpoint != "" || value.ServerName != "" {
			return errors.New("local connection cannot contain network fields")
		}
		return nil
	}
	if value.RemoteEndpoint == "" && value.ServerName == "" {
		return nil
	}
	return value.validate()
}

func (value Connection) validate() error {
	if !slices.Contains([]Transport{TransportLocalSocket, TransportTLS, TransportSandbox}, value.Transport) {
		return errors.New("connection transport is invalid")
	}
	if value.Transport == TransportLocalSocket || value.Transport == TransportSandbox {
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
