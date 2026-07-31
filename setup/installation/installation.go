// Package installation defines the durable, nonsecret source for guided server setup.
package installation

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/osolmaz/unyolo/internal/strictjson"
	setupintent "github.com/osolmaz/unyolo/setup/intent"
)

const (
	APIVersion      = "unyolo.io/installation/v1"
	DefaultName     = "default"
	MaxDocumentSize = 1024 * 1024
	MaxApprovers    = 32
	MaxConnections  = 32
)

var namePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)

type Approver struct {
	ID      string `json:"id"`
	Account string `json:"account"`
}

type TargetKind string

const (
	TargetLocalAccount TargetKind = "local_account"
	TargetContainer    TargetKind = "container"
	TargetRemote       TargetKind = "remote"
)

type Target struct {
	Kind             TargetKind              `json:"kind"`
	Isolation        string                  `json:"isolation"`
	AccountMode      setupintent.AccountMode `json:"account_mode,omitempty"`
	Account          string                  `json:"account,omitempty"`
	Home             string                  `json:"home,omitempty"`
	Shell            string                  `json:"shell,omitempty"`
	UID              int                     `json:"uid,omitempty"`
	GID              int                     `json:"gid,omitempty"`
	ProjectDirectory string                  `json:"project_directory,omitempty"`
	Service          string                  `json:"service,omitempty"`
	RemoteName       string                  `json:"remote_name,omitempty"`
}

type Connection struct {
	ID           string   `json:"id"`
	ClientID     string   `json:"client_id"`
	Target       Target   `json:"target"`
	Providers    []string `json:"providers"`
	Integrations []string `json:"integrations,omitempty"`
}

// Installation is the only editable source for one guided server installation.
type Installation struct {
	APIVersion        string                        `json:"api_version"`
	Name              string                        `json:"name"`
	CredentialService setupintent.CredentialService `json:"credential_service"`
	Approvers         []Approver                    `json:"approvers"`
	Connections       []Connection                  `json:"connections"`
}

func Decode(data []byte) (Installation, error) {
	if len(data) == 0 || len(data) > MaxDocumentSize {
		return Installation{}, errors.New("installation size is invalid")
	}
	var value Installation
	if err := strictjson.Decode(data, &value, true); err != nil {
		return Installation{}, fmt.Errorf("decode installation: %w", err)
	}
	if err := value.Validate(); err != nil {
		return Installation{}, err
	}
	return value, nil
}

func (value Installation) Validate() error {
	if value.APIVersion != APIVersion || !validName(value.Name) {
		return errors.New("installation identity is invalid")
	}
	serviceIntent := setupintent.Intent{APIVersion: setupintent.APIVersion, Goal: setupintent.GoalCredentialService, CredentialService: &value.CredentialService}
	if err := serviceIntent.Validate(); err != nil {
		return fmt.Errorf("installation credential service: %w", err)
	}
	if len(value.Approvers) == 0 || len(value.Approvers) > MaxApprovers || len(value.Connections) > MaxConnections {
		return errors.New("installation approver or connection count is invalid")
	}
	approvers := map[string]bool{}
	for _, approver := range value.Approvers {
		if !validName(approver.ID) || !validAccount(approver.Account) || approvers[approver.ID] {
			return errors.New("installation approver is invalid or duplicated")
		}
		approvers[approver.ID] = true
	}
	connections, clients := map[string]bool{}, map[string]bool{}
	providers := toSet(value.CredentialService.Providers)
	for _, connection := range value.Connections {
		if !validName(connection.ID) || !validName(connection.ClientID) || connections[connection.ID] || clients[connection.ClientID] ||
			len(connection.Providers) == 0 || !uniqueSubset(connection.Providers, providers) || !uniqueNames(connection.Integrations) {
			return errors.New("installation connection is invalid or duplicated")
		}
		if err := connection.Target.validate(); err != nil {
			return fmt.Errorf("connection %q target: %w", connection.ID, err)
		}
		connections[connection.ID], clients[connection.ClientID] = true, true
	}
	return nil
}

func (value Installation) Canonical() ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	slices.Sort(value.CredentialService.Providers)
	slices.SortFunc(value.Approvers, func(a, b Approver) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(value.Connections, func(a, b Connection) int { return strings.Compare(a.ID, b.ID) })
	for index := range value.Connections {
		slices.Sort(value.Connections[index].Providers)
		slices.Sort(value.Connections[index].Integrations)
	}
	data, err := json.MarshalIndent(value, "", "  ")
	return append(data, '\n'), err
}

func (value Installation) Digest() (string, error) {
	data, err := value.Canonical()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(data)), nil
}

func (value Target) validate() error {
	if !slices.Contains([]string{"separate", "container", "remote", "reduced"}, value.Isolation) {
		return errors.New("target isolation is invalid")
	}
	switch value.Kind {
	case TargetLocalAccount:
		if !slices.Contains([]string{"separate", "reduced"}, value.Isolation) || !slices.Contains([]setupintent.AccountMode{setupintent.AccountCurrent, setupintent.AccountExisting, setupintent.AccountManaged}, value.AccountMode) ||
			!validAccount(value.Account) || !filepath.IsAbs(value.Home) || filepath.Clean(value.Home) != value.Home || !filepath.IsAbs(value.Shell) || filepath.Clean(value.Shell) != value.Shell ||
			value.UID < 0 || value.GID < 0 || value.ProjectDirectory != "" || value.Service != "" || value.RemoteName != "" {
			return errors.New("local account target is invalid")
		}
	case TargetContainer:
		if value.Isolation != "container" || value.AccountMode != "" || value.Account != "" || value.Home != "" || value.Shell != "" || value.UID != 0 || value.GID != 0 || !filepath.IsAbs(value.ProjectDirectory) || filepath.Clean(value.ProjectDirectory) != value.ProjectDirectory ||
			!validName(value.Service) || value.RemoteName != "" {
			return errors.New("container target is invalid")
		}
	case TargetRemote:
		if value.Isolation != "remote" || value.AccountMode != "" || value.Account != "" || value.Home != "" || value.Shell != "" || value.UID != 0 || value.GID != 0 || value.ProjectDirectory != "" || value.Service != "" || !validName(value.RemoteName) {
			return errors.New("remote target is invalid")
		}
	default:
		return errors.New("target kind is invalid")
	}
	return nil
}

func toSet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func uniqueSubset(values []string, allowed map[string]bool) bool {
	seen := map[string]bool{}
	for _, value := range values {
		if !validName(value) || !allowed[value] || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func uniqueNames(values []string) bool { return uniqueSubset(values, toSet(values)) }
func validName(value string) bool      { return len(value) <= 64 && namePattern.MatchString(value) }
func validAccount(value string) bool {
	return validName(value) && !strings.ContainsAny(value, "\x00\r\n")
}
