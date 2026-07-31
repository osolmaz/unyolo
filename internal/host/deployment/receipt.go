package deployment

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/osolmaz/unyolo/deployment/api"
	componentprofile "github.com/osolmaz/unyolo/deployment/component"
	"github.com/osolmaz/unyolo/deployment/profile"
	"github.com/osolmaz/unyolo/internal/host/identity"
	"github.com/osolmaz/unyolo/internal/strictjson"
	"github.com/osolmaz/unyolo/setup/sourceset"
)

// ReceiptAPIVersion identifies the ownership receipt schema.
const ReceiptAPIVersion = "unyolo.io/ownership-receipt/v1"

const (
	maxReceiptBytes     = 4 * 1024 * 1024
	receiptFilename     = "ownership-receipt.json"
	pendingReceiptName  = "ownership-receipt.pending.json"
	maxReceiptAccounts  = 128
	maxReceiptGroups    = 128
	maxReceiptServices  = 128
	maxReceiptConns     = 128
	maxReceiptCompos    = 64
	maxReceiptResources = 2048
)

var (
	receiptDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	receiptNamePattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)
	receiptBundlePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// Receipt is one durable nonsecret ownership record for a live host installation.
type Receipt struct {
	APIVersion         string              `json:"api_version"`
	InstallationName   string              `json:"installation_name"`
	InstallationDigest string              `json:"installation_digest"`
	DeploymentName     string              `json:"deployment_name"`
	DeploymentDigest   string              `json:"deployment_digest"`
	RuntimeBundleID    string              `json:"runtime_bundle_id"`
	RuntimeBundleIDs   []string            `json:"runtime_bundle_ids"`
	BaselineBundleID   string              `json:"baseline_bundle_id,omitempty"`
	RecordedAt         time.Time           `json:"recorded_at"`
	Accounts           []AccountReceipt    `json:"accounts,omitempty"`
	Groups             []GroupReceipt      `json:"groups,omitempty"`
	Services           []ServiceReceipt    `json:"services,omitempty"`
	Connections        []ConnectionReceipt `json:"connections,omitempty"`
	Components         []ComponentReceipt  `json:"components,omitempty"`
	Resources          []ResourceReceipt   `json:"resources,omitempty"`
	RemovedResources   []string            `json:"removed_resources,omitempty"`
}

// AccountReceipt records one host account known to this installation.
type AccountReceipt struct {
	ID              string `json:"id"`
	UnixUser        string `json:"unix_user"`
	Mode            string `json:"mode"`
	Home            string `json:"home,omitempty"`
	Shell           string `json:"shell,omitempty"`
	Created         bool   `json:"created"`
	HomeFingerprint string `json:"home_fingerprint,omitempty"`
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

// ResourceReceipt records one adapter-owned resource without secret bytes.
type ResourceReceipt struct {
	ComponentID string `json:"component_id"`
	ActionID    string `json:"action_id"`
	Kind        string `json:"kind"`
	ID          string `json:"id"`
	Path        string `json:"path,omitempty"`
	Home        string `json:"home,omitempty"`
	Shell       string `json:"shell,omitempty"`
	Group       string `json:"group,omitempty"`
	Created     bool   `json:"created"`
	Data        bool   `json:"data,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
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
		!receiptDigestPattern.MatchString(value.DeploymentDigest) || !receiptBundlePattern.MatchString(value.RuntimeBundleID) ||
		value.BaselineBundleID != "" && !receiptBundlePattern.MatchString(value.BaselineBundleID) {
		return errors.New("ownership receipt digest identity is invalid")
	}
	if len(value.RuntimeBundleIDs) == 0 || len(value.RuntimeBundleIDs) > 64 {
		return errors.New("ownership receipt runtime history is invalid")
	}
	seenBundles := map[string]bool{}
	for _, bundleID := range value.RuntimeBundleIDs {
		if !receiptBundlePattern.MatchString(bundleID) || seenBundles[bundleID] {
			return errors.New("ownership receipt runtime history is invalid or duplicated")
		}
		seenBundles[bundleID] = true
	}
	if !seenBundles[value.RuntimeBundleID] {
		return errors.New("ownership receipt active runtime is absent from its history")
	}
	if value.RecordedAt.IsZero() {
		return errors.New("ownership receipt is missing a recorded time")
	}
	if len(value.Accounts) > maxReceiptAccounts || len(value.Groups) > maxReceiptGroups ||
		len(value.Services) > maxReceiptServices || len(value.Connections) > maxReceiptConns ||
		len(value.Components) > maxReceiptCompos || len(value.Resources) > maxReceiptResources || len(value.RemovedResources) > maxReceiptResources {
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
		if account.HomeFingerprint != "" && !receiptDigestPattern.MatchString(account.HomeFingerprint) {
			return errors.New("ownership receipt account home fingerprint is invalid")
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
	seenRemoved := map[string]bool{}
	for _, key := range value.RemovedResources {
		if !receiptDigestPattern.MatchString(key) || seenRemoved[key] {
			return errors.New("ownership receipt removed resource is invalid or duplicated")
		}
		seenRemoved[key] = true
	}
	seenResources := map[string]bool{}
	for _, resource := range value.Resources {
		key := resource.ComponentID + "\x00" + resource.ActionID
		if !receiptNamePattern.MatchString(resource.ComponentID) || strings.TrimSpace(resource.ActionID) == "" ||
			strings.TrimSpace(resource.Kind) == "" || strings.TrimSpace(resource.ID) == "" || seenResources[key] {
			return errors.New("ownership receipt resource is invalid or duplicated")
		}
		for _, path := range []string{resource.Path, resource.Home, resource.Shell} {
			if path != "" && (!filepath.IsAbs(path) || filepath.Clean(path) != path) {
				return errors.New("ownership receipt resource path is invalid")
			}
		}
		if resource.Fingerprint != "" && !receiptDigestPattern.MatchString(resource.Fingerprint) {
			return errors.New("ownership receipt resource fingerprint is invalid")
		}
		seenResources[key] = true
	}
	return nil
}

// ReceiptFromPlan derives a pending receipt without reading post-apply state.
func ReceiptFromPlan(planned Planned, installationName string, recorded time.Time) (Receipt, error) {
	return ReceiptFromPlanContext(context.Background(), planned, installationName, recorded, false)
}

// ReceiptFromPlanContext derives a receipt and optionally records exact
// post-apply fingerprints for every changed adapter resource.
func ReceiptFromPlanContext(ctx context.Context, planned Planned, installationName string, recorded time.Time, capturePostApply bool) (Receipt, error) {
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
		RuntimeBundleIDs:   []string{planned.Snapshot.Manifest.BundleID},
		RecordedAt:         recorded.UTC(),
	}
	if planned.ActiveBundleID != planned.Snapshot.Manifest.BundleID {
		receipt.BaselineBundleID = planned.ActiveBundleID
	}
	if receipt.InstallationDigest == "" {
		// Advanced locked profile deployments have no installation source.
		receipt.InstallationDigest = receipt.DeploymentDigest
		if installationName == "" {
			receipt.InstallationName = planned.Snapshot.Deployment.Name
		}
	}
	if err := populateReceiptAgents(ctx, &receipt, planned.Snapshot, planned.Accounts, capturePostApply); err != nil {
		return Receipt{}, err
	}
	populateReceiptServices(&receipt, planned.Snapshot)
	populateReceiptComponents(&receipt, planned)
	if err := populateReceiptResources(ctx, &receipt, planned, capturePostApply); err != nil {
		return Receipt{}, err
	}
	for _, resource := range planned.StaleClients {
		receipt.RemovedResources = append(receipt.RemovedResources, resourceReceiptKey(resource))
	}
	slices.Sort(receipt.RemovedResources)
	if err := receipt.Validate(); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func populateReceiptAgents(ctx context.Context, receipt *Receipt, snapshot profile.Snapshot, accounts map[string]identity.Account, capturePostApply bool) error {
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
		if entry.Created && capturePostApply {
			fingerprint, err := sourceset.Digest(entry.Home)
			if err != nil {
				return fmt.Errorf("fingerprint managed account home %q: %w", entry.UnixUser, err)
			}
			entry.HomeFingerprint = fingerprint
		}
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
		receipt.Groups = append(receipt.Groups, GroupReceipt{Name: account.UnixUser, Created: true})
	}
	slices.SortFunc(receipt.Groups, func(a, b GroupReceipt) int { return strings.Compare(a.Name, b.Name) })
	return nil
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

func populateReceiptResources(ctx context.Context, receipt *Receipt, planned Planned, capturePostApply bool) error {
	hasResources := false
	for _, response := range planned.Responses {
		hasResources = hasResources || response.ComponentID != "host-identity" && len(response.Actions) > 0
	}
	if !hasResources {
		return nil
	}
	profiles, err := receiptComponentProfiles(planned.Snapshot)
	if err != nil {
		return err
	}
	stateDirs := map[string]string{}
	for _, runtimeComponent := range planned.Snapshot.Manifest.Components {
		stateDirs[runtimeComponent.Name] = runtimeComponent.StateDir
	}
	for _, response := range planned.Responses {
		if response.ComponentID == "host-identity" || response.ComponentID == "host-cleanup" {
			continue
		}
		componentProfile := profiles[response.ComponentID]
		for _, action := range response.Actions {
			resource := ResourceReceipt{
				ComponentID: response.ComponentID, ActionID: action.ID, Kind: action.Resource.Kind,
				ID: action.Resource.ID, Path: action.Resource.Path, Created: action.CurrentState == "missing",
			}
			enrichResourceReceipt(&resource, componentProfile)
			resource.Data = resourceContainsData(resource, stateDirs[response.ComponentID])
			if capturePostApply {
				resource.Fingerprint = receiptResourceFingerprint(ctx, resource)
				if !receiptDigestPattern.MatchString(resource.Fingerprint) {
					return fmt.Errorf("capture post-apply fingerprint for %s resource %q", resource.Kind, resource.ID)
				}
			}
			receipt.Resources = append(receipt.Resources, resource)
		}
	}
	dataGroups := map[string]bool{}
	for _, resource := range receipt.Resources {
		if resource.Kind == "account" && resource.Data && resource.Group != "" {
			dataGroups[resource.Group] = true
		}
	}
	for index := range receipt.Resources {
		if receipt.Resources[index].Kind == "group" && dataGroups[receipt.Resources[index].ID] {
			receipt.Resources[index].Data = true
		}
		if receipt.Resources[index].Kind != "directory" || receipt.Resources[index].Path == "" {
			continue
		}
		for _, child := range receipt.Resources {
			if child.Data && child.Path != "" && strings.HasPrefix(child.Path, receipt.Resources[index].Path+string(filepath.Separator)) {
				receipt.Resources[index].Data = true
				break
			}
		}
	}
	slices.SortFunc(receipt.Resources, func(a, b ResourceReceipt) int {
		if a.ComponentID != b.ComponentID {
			return strings.Compare(a.ComponentID, b.ComponentID)
		}
		return strings.Compare(a.ActionID, b.ActionID)
	})
	return nil
}

func receiptComponentProfiles(snapshot profile.Snapshot) (map[string]componentprofile.Profile, error) {
	result := map[string]componentprofile.Profile{}
	for _, reference := range deploymentComponents(snapshot) {
		file, exists := snapshot.Files[reference.Profile.Path]
		if !exists {
			return nil, fmt.Errorf("component %q profile is unavailable for receipt", reference.ID)
		}
		var value componentprofile.Profile
		if err := strictjson.Decode(file.Data, &value, true); err != nil {
			return nil, err
		}
		result[reference.ID] = value
	}
	return result, nil
}

func enrichResourceReceipt(receipt *ResourceReceipt, value componentprofile.Profile) {
	switch receipt.Kind {
	case "account":
		for _, account := range value.Accounts {
			if account.Name == receipt.ID {
				receipt.Home, receipt.Shell, receipt.Group = account.Home, account.Shell, account.Group
				return
			}
		}
	case "group":
		return
	case "directory":
		for _, directory := range value.Directories {
			if directory.ID == receipt.ID {
				receipt.Path = directory.Destination
				return
			}
		}
	case "file":
		for _, managed := range value.Files {
			if managed.ID == receipt.ID {
				receipt.Path = managed.Destination
				return
			}
		}
	}
}

func receiptResourceFingerprint(ctx context.Context, resource ResourceReceipt) string {
	if resource.Kind == "directory" && resource.Data {
		return dataTreeFingerprint(ctx, resource.Path)
	}
	includeContent := resource.Kind == "client" || resource.Kind == "file" && !resource.Data
	return componentprofile.ResourceFingerprint(ctx, api.Resource{Kind: resource.Kind, ID: resource.ID, Path: resource.Path}, includeContent)
}

func dataTreeFingerprint(ctx context.Context, root string) string {
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return "missing"
	} else if err != nil {
		return "unavailable"
	}
	hash := sha256.New()
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		fingerprint := componentprofile.ResourceFingerprint(ctx, api.Resource{Kind: "file", Path: path}, false)
		if !receiptDigestPattern.MatchString(fingerprint) {
			return fmt.Errorf("fingerprint %s: %s", relative, fingerprint)
		}
		_, _ = fmt.Fprintf(hash, "%s\x00%s\x00%d\x00", filepath.ToSlash(relative), fingerprint, entry.Type())
		return nil
	}); err != nil {
		return "unavailable"
	}
	return fmt.Sprintf("sha256:%x", hash.Sum(nil))
}

func resourceReceiptKey(resource ResourceReceipt) string {
	value := strings.Join([]string{resource.ComponentID, resource.ActionID, resource.Kind, resource.ID, resource.Path}, "\x00")
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(value)))
}

func resourceContainsData(resource ResourceReceipt, stateDir string) bool {
	if slices.Contains([]string{"credential", "secret_store", "account"}, resource.Kind) {
		return true
	}
	return stateDir != "" && resource.Path != "" &&
		(resource.Path == stateDir || strings.HasPrefix(resource.Path, stateDir+string(filepath.Separator)))
}

// MergeReceipt preserves original ownership and runtime baselines across
// repair and reconfiguration while refreshing current fingerprints.
func MergeReceipt(previous, current Receipt) (Receipt, error) {
	if previous.APIVersion == "" {
		return current, current.Validate()
	}
	if err := previous.Validate(); err != nil {
		return Receipt{}, err
	}
	if previous.InstallationName != current.InstallationName {
		return Receipt{}, errors.New("ownership receipt belongs to another installation")
	}
	current.BaselineBundleID = previous.BaselineBundleID
	seenBundles := map[string]bool{}
	current.RuntimeBundleIDs = nil
	for _, bundleID := range append(append([]string(nil), previous.RuntimeBundleIDs...), current.RuntimeBundleID) {
		if !seenBundles[bundleID] {
			current.RuntimeBundleIDs = append(current.RuntimeBundleIDs, bundleID)
			seenBundles[bundleID] = true
		}
	}
	priorAccounts := map[string]AccountReceipt{}
	for _, account := range previous.Accounts {
		priorAccounts[account.ID] = account
	}
	for index := range current.Accounts {
		if prior, exists := priorAccounts[current.Accounts[index].ID]; exists && prior.Created {
			current.Accounts[index].Created = true
			if current.Accounts[index].HomeFingerprint == "" {
				current.Accounts[index].HomeFingerprint = prior.HomeFingerprint
			}
		}
		delete(priorAccounts, current.Accounts[index].ID)
	}
	for _, account := range priorAccounts {
		current.Accounts = append(current.Accounts, account)
	}
	seenGroups := map[string]bool{}
	for _, group := range current.Groups {
		seenGroups[group.Name] = true
	}
	for _, group := range previous.Groups {
		if !seenGroups[group.Name] {
			current.Groups = append(current.Groups, group)
		}
	}
	removedResources := map[string]bool{}
	for _, key := range current.RemovedResources {
		removedResources[key] = true
	}
	priorResources := map[string]ResourceReceipt{}
	for _, resource := range previous.Resources {
		if !removedResources[resourceReceiptKey(resource)] {
			priorResources[resource.ComponentID+"\x00"+resource.ActionID] = resource
		}
	}
	current.RemovedResources = nil
	for index := range current.Resources {
		key := current.Resources[index].ComponentID + "\x00" + current.Resources[index].ActionID
		if prior, exists := priorResources[key]; exists && prior.Created {
			current.Resources[index].Created = true
		}
		delete(priorResources, key)
	}
	for _, resource := range priorResources {
		current.Resources = append(current.Resources, resource)
	}
	slices.SortFunc(current.Accounts, func(a, b AccountReceipt) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(current.Groups, func(a, b GroupReceipt) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(current.Resources, func(a, b ResourceReceipt) int {
		if a.ComponentID != b.ComponentID {
			return strings.Compare(a.ComponentID, b.ComponentID)
		}
		return strings.Compare(a.ActionID, b.ActionID)
	})
	return current, current.Validate()
}

// RefreshReceiptFingerprints captures current post-apply identities for a
// pending receipt after crash recovery or a committed transaction.
func RefreshReceiptFingerprints(ctx context.Context, value Receipt) (Receipt, error) {
	for index := range value.Resources {
		resource := &value.Resources[index]
		fingerprint := receiptResourceFingerprint(ctx, *resource)
		if !receiptDigestPattern.MatchString(fingerprint) {
			return Receipt{}, fmt.Errorf("refresh fingerprint for %s resource %q", resource.Kind, resource.ID)
		}
		resource.Fingerprint = fingerprint
	}
	value.RecordedAt = time.Now().UTC()
	return value, value.Validate()
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
	return loadReceiptPath(path)
}

func loadReceiptPath(path string) (Receipt, bool, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- fixed root-owned receipt path.
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
	path, err := ReceiptPath(stateDir)
	if err != nil {
		return err
	}
	return saveReceiptAt(stateDir, path, receipt)
}

// StagePendingReceipt preserves ownership evidence before host mutation.
func StagePendingReceipt(stateDir string, receipt Receipt) error {
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return errors.New("ownership receipt state directory is invalid")
	}
	return saveReceiptAt(stateDir, filepath.Join(stateDir, pendingReceiptName), receipt)
}

// LoadPendingReceipt reads a staged ownership receipt.
func LoadPendingReceipt(stateDir string) (Receipt, bool, error) {
	return loadReceiptPath(filepath.Join(stateDir, pendingReceiptName))
}

// DiscardPendingReceipt removes staged ownership evidence after rollback.
func DiscardPendingReceipt(stateDir string) error {
	if err := os.Remove(filepath.Join(stateDir, pendingReceiptName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func saveReceiptAt(stateDir, path string, receipt Receipt) error {
	if err := receipt.Validate(); err != nil {
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
	if err := os.Rename(name, path); err != nil {
		return err
	}
	directory, err := os.Open(stateDir) // #nosec G304 -- validated root-owned state directory.
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
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
