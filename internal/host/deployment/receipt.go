package deployment

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/osolmaz/unyolo/deployment/profile"
	"github.com/osolmaz/unyolo/internal/host/identity"
	"github.com/osolmaz/unyolo/internal/strictjson"
)

// ReceiptAPIVersion identifies the ownership receipt schema.
const ReceiptAPIVersion = "unyolo.io/ownership-receipt/v1"

const (
	maxReceiptBytes    = 1 * 1024 * 1024
	receiptFilename    = "ownership-receipt.json"
	maxReceiptAccounts = 128
	maxReceiptGroups   = 128
	maxReceiptServices = 128
	maxReceiptConns    = 128
	maxReceiptCompos   = 64
)

var (
	receiptDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	receiptNamePattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)
)

// Receipt is one durable nonsecret ownership record for a live host installation.
type Receipt struct {
	APIVersion         string              `json:"api_version"`
	InstallationName   string              `json:"installation_name"`
	InstallationDigest string              `json:"installation_digest"`
	DeploymentName     string              `json:"deployment_name"`
	DeploymentDigest   string              `json:"deployment_digest"`
	RuntimeBundleID    string              `json:"runtime_bundle_id"`
	RecordedAt         time.Time           `json:"recorded_at"`
	Accounts           []AccountReceipt    `json:"accounts,omitempty"`
	Groups             []GroupReceipt      `json:"groups,omitempty"`
	Services           []ServiceReceipt    `json:"services,omitempty"`
	Connections        []ConnectionReceipt `json:"connections,omitempty"`
	Components         []ComponentReceipt  `json:"components,omitempty"`
}

// AccountReceipt records one host account known to this installation.
type AccountReceipt struct {
	ID       string `json:"id"`
	UnixUser string `json:"unix_user"`
	Mode     string `json:"mode"`
	Home     string `json:"home,omitempty"`
	Shell    string `json:"shell,omitempty"`
	Created  bool   `json:"created"`
}

// GroupReceipt records one host group known to this installation.
type GroupReceipt struct {
	Name    string `json:"name"`
	Created bool   `json:"created"`
}

// ServiceReceipt binds one enabled native service to its owning component.
type ServiceReceipt struct {
	Name      string `json:"name"`
	Component string `json:"component"`
}

// ConnectionReceipt records one managed agent connection without secret values.
type ConnectionReceipt struct {
	ID       string `json:"id"`
	ClientID string `json:"client_id"`
}

// ComponentReceipt records one adapter's plan identity for later removal.
type ComponentReceipt struct {
	ID         string `json:"id"`
	PlanDigest string `json:"plan_digest,omitempty"`
}

// Validate rejects malformed or secret-like receipt content.
//
//nolint:cyclop // Receipts persist across host lifecycles; each bounded field is checked at the trust boundary.
func (value Receipt) Validate() error {
	if value.APIVersion != ReceiptAPIVersion || !receiptNamePattern.MatchString(value.InstallationName) ||
		!receiptNamePattern.MatchString(value.DeploymentName) {
		return errors.New("ownership receipt identity is invalid")
	}
	if !receiptDigestPattern.MatchString(value.InstallationDigest) ||
		!receiptDigestPattern.MatchString(value.DeploymentDigest) || value.RuntimeBundleID == "" {
		return errors.New("ownership receipt digest identity is invalid")
	}
	if value.RecordedAt.IsZero() {
		return errors.New("ownership receipt is missing a recorded time")
	}
	if len(value.Accounts) > maxReceiptAccounts || len(value.Groups) > maxReceiptGroups ||
		len(value.Services) > maxReceiptServices || len(value.Connections) > maxReceiptConns ||
		len(value.Components) > maxReceiptCompos {
		return errors.New("ownership receipt exceeds collection limits")
	}
	seenAccounts := map[string]bool{}
	for _, account := range value.Accounts {
		if !receiptNamePattern.MatchString(account.ID) || strings.TrimSpace(account.UnixUser) == "" ||
			seenAccounts[account.ID] {
			return errors.New("ownership receipt account is invalid or duplicated")
		}
		if !slices.Contains([]string{"managed", "existing", "current"}, account.Mode) {
			return errors.New("ownership receipt account mode is invalid")
		}
		if account.Home != "" && (!filepath.IsAbs(account.Home) || filepath.Clean(account.Home) != account.Home) {
			return errors.New("ownership receipt account home is invalid")
		}
		if account.Shell != "" && (!filepath.IsAbs(account.Shell) || filepath.Clean(account.Shell) != account.Shell) {
			return errors.New("ownership receipt account shell is invalid")
		}
		seenAccounts[account.ID] = true
	}
	seenGroups := map[string]bool{}
	for _, group := range value.Groups {
		if strings.TrimSpace(group.Name) == "" || seenGroups[group.Name] {
			return errors.New("ownership receipt group is invalid or duplicated")
		}
		seenGroups[group.Name] = true
	}
	seenServices := map[string]bool{}
	for _, service := range value.Services {
		if strings.TrimSpace(service.Name) == "" || strings.TrimSpace(service.Component) == "" ||
			seenServices[service.Name] {
			return errors.New("ownership receipt service is invalid or duplicated")
		}
		seenServices[service.Name] = true
	}
	seenConns := map[string]bool{}
	for _, connection := range value.Connections {
		if !receiptNamePattern.MatchString(connection.ID) || !receiptNamePattern.MatchString(connection.ClientID) ||
			seenConns[connection.ID] {
			return errors.New("ownership receipt connection is invalid or duplicated")
		}
		seenConns[connection.ID] = true
	}
	seenComponents := map[string]bool{}
	for _, component := range value.Components {
		if !receiptNamePattern.MatchString(component.ID) || seenComponents[component.ID] {
			return errors.New("ownership receipt component is invalid or duplicated")
		}
		if component.PlanDigest != "" && !receiptDigestPattern.MatchString(component.PlanDigest) {
			return errors.New("ownership receipt component plan digest is invalid")
		}
		seenComponents[component.ID] = true
	}
	return nil
}

// ReceiptFromPlan derives one durable receipt from a planned deployment.
func ReceiptFromPlan(planned Planned, installationName string, recorded time.Time) (Receipt, error) {
	if recorded.IsZero() {
		return Receipt{}, errors.New("ownership receipt requires a recorded time")
	}
	if installationName == "" {
		installationName = "default"
	}
	receipt := Receipt{
		APIVersion:         ReceiptAPIVersion,
		InstallationName:   installationName,
		InstallationDigest: planned.Snapshot.Deployment.InstallationDigest,
		DeploymentName:     planned.Snapshot.Deployment.Name,
		DeploymentDigest:   planned.Snapshot.Digest,
		RuntimeBundleID:    planned.Snapshot.Manifest.BundleID,
		RecordedAt:         recorded.UTC(),
	}
	if receipt.InstallationDigest == "" {
		// Advanced locked profile deployments have no installation source.
		receipt.InstallationDigest = receipt.DeploymentDigest
		if installationName == "" {
			receipt.InstallationName = planned.Snapshot.Deployment.Name
		}
	}
	populateReceiptAgents(&receipt, planned.Snapshot, planned.Accounts)
	populateReceiptServices(&receipt, planned.Snapshot)
	populateReceiptComponents(&receipt, planned)
	if err := receipt.Validate(); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func populateReceiptAgents(receipt *Receipt, snapshot profile.Snapshot, accounts map[string]identity.Account) {
	seenGroups := map[string]bool{}
	for _, agent := range snapshot.Deployment.Agents {
		if agent.Target.Kind != "local_account" {
			receipt.Connections = append(receipt.Connections, ConnectionReceipt{ID: agent.ID, ClientID: agent.ClientID})
			continue
		}
		account := accounts["agent:"+agent.ID]
		entry := AccountReceipt{
			ID: agent.ID, UnixUser: agent.Target.UnixUser, Mode: agent.Target.AccountMode,
			Home: agent.Target.Home, Shell: agent.Target.Shell,
		}
		// A managed account is created by unYOLO when the identity inspector reports it missing.
		// An existing or current account is never created.
		entry.Created = agent.Target.AccountMode == "managed" && account.Missing
		receipt.Accounts = append(receipt.Accounts, entry)
		receipt.Connections = append(receipt.Connections, ConnectionReceipt{ID: agent.ID, ClientID: agent.ClientID})
	}
	slices.SortFunc(receipt.Accounts, func(a, b AccountReceipt) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(receipt.Connections, func(a, b ConnectionReceipt) int { return strings.Compare(a.ID, b.ID) })
	// Managed accounts are the only groups the engine level directly manages;
	// component-managed groups appear in provider receipts. Deduplicate defensively.
	for _, account := range receipt.Accounts {
		if !account.Created {
			continue
		}
		if seenGroups[account.UnixUser] {
			continue
		}
		seenGroups[account.UnixUser] = true
	}
}

func populateReceiptServices(receipt *Receipt, snapshot profile.Snapshot) {
	for _, component := range snapshot.Manifest.Components {
		for _, service := range component.Services {
			receipt.Services = append(receipt.Services, ServiceReceipt{Name: service, Component: component.Name})
		}
	}
	slices.SortFunc(receipt.Services, func(a, b ServiceReceipt) int { return strings.Compare(a.Name, b.Name) })
}

func populateReceiptComponents(receipt *Receipt, planned Planned) {
	responses := map[string]string{}
	for _, response := range planned.Responses {
		responses[response.ComponentID] = response.PlanDigest
	}
	for _, component := range deploymentComponents(planned.Snapshot) {
		receipt.Components = append(receipt.Components, ComponentReceipt{ID: component.ID, PlanDigest: responses[component.ID]})
	}
	slices.SortFunc(receipt.Components, func(a, b ComponentReceipt) int { return strings.Compare(a.ID, b.ID) })
}

// ReceiptPath returns the fixed root-owned receipt filesystem path.
func ReceiptPath(stateDir string) (string, error) {
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return "", errors.New("ownership receipt state directory is invalid")
	}
	return filepath.Join(stateDir, receiptFilename), nil
}

// LoadReceipt reads and validates one ownership receipt if present.
func LoadReceipt(stateDir string) (Receipt, bool, error) {
	path, err := ReceiptPath(stateDir)
	if err != nil {
		return Receipt{}, false, err
	}
	data, err := os.ReadFile(path) // #nosec G304 -- fixed host state path.
	if errors.Is(err, os.ErrNotExist) {
		return Receipt{}, false, nil
	}
	if err != nil {
		return Receipt{}, false, err
	}
	if len(data) == 0 || len(data) > maxReceiptBytes {
		return Receipt{}, false, errors.New("ownership receipt exceeds size limits")
	}
	var value Receipt
	if err := strictjson.Decode(data, &value, true); err != nil {
		return Receipt{}, false, fmt.Errorf("decode ownership receipt: %w", err)
	}
	if err := value.Validate(); err != nil {
		return Receipt{}, false, err
	}
	return value, true, nil
}

// SaveReceipt writes one ownership receipt atomically under its fixed path.
func SaveReceipt(stateDir string, receipt Receipt) error {
	if err := receipt.Validate(); err != nil {
		return err
	}
	path, err := ReceiptPath(stateDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > maxReceiptBytes {
		return errors.New("ownership receipt exceeds size limits")
	}
	temporary, err := os.CreateTemp(stateDir, ".receipt-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer func() { _ = os.Remove(name) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// DeleteReceipt removes any ownership receipt at its fixed path.
func DeleteReceipt(stateDir string) error {
	path, err := ReceiptPath(stateDir)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
