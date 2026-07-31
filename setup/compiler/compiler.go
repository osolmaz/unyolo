// Package compiler deterministically renders a guided installation into one locked host deployment.
package compiler

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/osolmaz/unyolo/deployment/component"
	"github.com/osolmaz/unyolo/deployment/profile"
	"github.com/osolmaz/unyolo/internal/host/bundle"
	"github.com/osolmaz/unyolo/internal/pathutil"
	"github.com/osolmaz/unyolo/internal/strictjson"
	"github.com/osolmaz/unyolo/setup/installation"
	"github.com/osolmaz/unyolo/setup/sourceset"
)

// SourceProviderAPIVersion identifies the canonical release source provider descriptor.
const SourceProviderAPIVersion = "unyolo.io/deployment-source-provider/v1"

// Options binds one guided installation to a verified release source set.
type Options struct {
	Installation installation.Installation
	SourceSet    string
	Destination  string
}

// SourceProvider describes one provider entry inside the canonical release
// source set. The file below the release directory pins the provider identifier
// to its owned runtime components, its signed ownership envelope, and its
// deployment profile and static assets.
type SourceProvider struct {
	APIVersion string                   `json:"api_version"`
	ID         string                   `json:"id"`
	Components []string                 `json:"components"`
	Ownership  bundle.OwnershipEnvelope `json:"ownership"`
	Profile    string                   `json:"profile"`
	Files      []string                 `json:"files,omitempty"`
}

// Compile renders one host deployment from the installation record, verified
// release source set, and destination path. It produces a byte-identical
// locked deployment pack for the same inputs.
//
//nolint:cyclop // Source-set compilation binds every provider, artifact, and runtime file into one locked pack.
func Compile(options Options) (profile.Snapshot, error) {
	if err := options.Installation.Validate(); err != nil {
		return profile.Snapshot{}, err
	}
	if !cleanAbsolute(options.SourceSet) || !cleanAbsolute(options.Destination) ||
		pathutil.Overlap(options.Destination, options.SourceSet) {
		return profile.Snapshot{}, errors.New("compiler paths are invalid")
	}
	if _, err := os.Lstat(options.Destination); !errors.Is(err, os.ErrNotExist) {
		return profile.Snapshot{}, errors.New("compiler destination already exists or is unavailable")
	}
	parent := filepath.Dir(options.Destination)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return profile.Snapshot{}, err
	}
	staging, err := os.MkdirTemp(parent, ".unyolo-installation-*")
	if err != nil {
		return profile.Snapshot{}, err
	}
	cleanup := func() { _ = os.RemoveAll(staging) }
	defer func() { cleanup() }()

	sourceDigest, err := sourceset.Digest(options.SourceSet)
	if err != nil {
		return profile.Snapshot{}, err
	}
	manifest, err := loadSourceManifest(options.SourceSet)
	if err != nil {
		return profile.Snapshot{}, err
	}
	selectedProviders, err := loadSelectedProviders(options.SourceSet, options.Installation.CredentialService.Providers)
	if err != nil {
		return profile.Snapshot{}, err
	}
	if err := copyRuntimeTrust(options.SourceSet, staging); err != nil {
		return profile.Snapshot{}, err
	}
	if err := copyProviderAssets(options.SourceSet, staging, selectedProviders); err != nil {
		return profile.Snapshot{}, err
	}
	if err := copyRuntimeArtifacts(options.SourceSet, staging, manifest, selectedProviders); err != nil {
		return profile.Snapshot{}, err
	}
	if err := renderProviderComponents(options.SourceSet, staging, options.Installation, selectedProviders); err != nil {
		return profile.Snapshot{}, err
	}
	deployment, err := compileDeployment(options.Installation, selectedProviders, manifest, sourceDigest)
	if err != nil {
		return profile.Snapshot{}, err
	}
	if err := writeJSON(filepath.Join(staging, profile.EntryFilename), deployment); err != nil {
		return profile.Snapshot{}, err
	}
	if err := profile.Lock(staging, false); err != nil {
		return profile.Snapshot{}, err
	}
	if err := validateOwnershipEnvelopes(staging, deployment, selectedProviders); err != nil {
		return profile.Snapshot{}, err
	}
	if err := os.Rename(staging, options.Destination); err != nil {
		return profile.Snapshot{}, err
	}
	cleanup = func() {}
	return profile.Load(options.Destination)
}

func loadSourceManifest(sourceSet string) (bundle.Manifest, error) {
	root := filepath.Join(sourceSet, "runtime")
	manifest, _, err := bundle.Load(
		filepath.Join(root, "manifest.json"),
		filepath.Join(root, "manifest.sig"),
		filepath.Join(root, "release.pub"),
		false,
	)
	return manifest, err
}

func loadSelectedProviders(sourceSet string, providers []string) ([]SourceProvider, error) {
	available := map[string]SourceProvider{}
	root := filepath.Join(sourceSet, "providers")
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, errors.New("provider source directory is unsafe")
		}
		data, readErr := os.ReadFile(filepath.Join(root, entry.Name(), "source.json")) // #nosec G304 -- validated child of the release source set.
		if readErr != nil {
			return nil, fmt.Errorf("read provider source %q: %w", entry.Name(), readErr)
		}
		var descriptor SourceProvider
		if decodeErr := strictjson.Decode(data, &descriptor, true); decodeErr != nil {
			return nil, fmt.Errorf("decode provider source %q: %w", entry.Name(), decodeErr)
		}
		if descriptor.APIVersion != SourceProviderAPIVersion || descriptor.ID != entry.Name() {
			return nil, fmt.Errorf("provider source %q identity is invalid", entry.Name())
		}
		available[descriptor.ID] = descriptor
	}
	result := make([]SourceProvider, 0, len(providers))
	sorted := append([]string(nil), providers...)
	slices.Sort(sorted)
	for _, id := range sorted {
		descriptor, exists := available[id]
		if !exists {
			return nil, fmt.Errorf("selected provider %q is absent from the release source set", id)
		}
		result = append(result, descriptor)
	}
	return result, nil
}

func copyRuntimeTrust(sourceSet, staging string) error {
	if err := os.MkdirAll(filepath.Join(staging, "runtime"), 0o700); err != nil {
		return err
	}
	for _, name := range []string{"manifest.json", "manifest.sig", "release.pub"} {
		source := filepath.Join(sourceSet, "runtime", name)
		data, err := readRegular(source, 2*1024*1024)
		if err != nil {
			return fmt.Errorf("read runtime trust file %q: %w", name, err)
		}
		if err := writeRelative(staging, filepath.Join("runtime", name), data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func copyProviderAssets(sourceSet, staging string, providers []SourceProvider) error {
	for _, provider := range providers {
		files := append([]string(nil), provider.Files...)
		slices.Sort(files)
		for _, file := range files {
			source := filepath.Join(sourceSet, "providers", provider.ID, filepath.FromSlash(file))
			data, err := readRegular(source, 4*1024*1024)
			if err != nil {
				return fmt.Errorf("copy provider %q asset %q: %w", provider.ID, file, err)
			}
			if err := writeRelative(staging, file, data, 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}

func copyRuntimeArtifacts(sourceSet, staging string, manifest bundle.Manifest, providers []SourceProvider) error {
	needed := map[string]bool{}
	for _, provider := range providers {
		for _, componentName := range provider.Components {
			needed[componentName] = true
		}
	}
	for _, runtimeComponent := range manifest.Components {
		if !needed[runtimeComponent.Name] {
			continue
		}
		source := filepath.Join(sourceSet, filepath.FromSlash(runtimeComponent.Source))
		data, err := readRegular(source, 256*1024*1024)
		if err != nil {
			return fmt.Errorf("copy runtime artifact %q: %w", runtimeComponent.Name, err)
		}
		if err := writeRelative(staging, runtimeComponent.Source, data, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func compileDeployment(source installation.Installation, providers []SourceProvider, manifest bundle.Manifest, sourceDigest string) (profile.Deployment, error) {
	digest, err := source.Digest()
	if err != nil {
		return profile.Deployment{}, err
	}
	deployment := profile.Deployment{
		APIVersion: profile.APIVersion, Name: source.Name, InstallationDigest: digest, SourceSetDigest: sourceDigest,
		Runtime: profile.Runtime{
			Manifest:  profile.Reference{Path: "runtime/manifest.json", SHA256: zeroDigest()},
			Signature: profile.Reference{Path: "runtime/manifest.sig", SHA256: zeroDigest()},
			PublicKey: profile.Reference{Path: "runtime/release.pub", SHA256: zeroDigest()},
		},
		Operators: nil,
		Agents:    nil,
	}
	for _, approver := range source.Approvers {
		deployment.Operators = append(deployment.Operators, profile.Operator{ID: approver.ID, UnixUser: approver.Account})
	}
	if len(deployment.Operators) == 0 {
		return profile.Deployment{}, errors.New("installation must have at least one approver")
	}
	for _, connection := range source.Connections {
		target := profile.AgentTarget{Kind: string(connection.Target.Kind), Isolation: connection.Target.Isolation}
		switch connection.Target.Kind {
		case installation.TargetLocalAccount:
			target.AccountMode, target.UnixUser, target.Home, target.Shell = string(connection.Target.AccountMode), connection.Target.Account, connection.Target.Home, connection.Target.Shell
		case installation.TargetContainer:
			target.ProjectDirectory, target.Service = connection.Target.ProjectDirectory, connection.Target.Service
		case installation.TargetRemote:
			target.RemoteName = connection.Target.RemoteName
		}
		componentIDs := append([]string(nil), connection.Providers...)
		slices.Sort(componentIDs)
		deployment.Agents = append(deployment.Agents, profile.Agent{ID: connection.ID, ClientID: connection.ClientID, Target: target, ComponentIDs: componentIDs})
	}
	for _, provider := range providers {
		deployment.Components = append(deployment.Components, profile.Component{
			ID: provider.ID, Profile: profile.Reference{Path: componentProfilePath(provider.ID), SHA256: zeroDigest()},
		})
	}
	// Ensure declared runtime manifest is not empty.
	if len(manifest.Components) == 0 {
		return profile.Deployment{}, errors.New("release runtime manifest declares no components")
	}
	if err := deployment.Validate(); err != nil {
		return profile.Deployment{}, err
	}
	return deployment, nil
}

func renderProviderComponents(sourceSet, staging string, source installation.Installation, providers []SourceProvider) error {
	if err := os.MkdirAll(filepath.Join(staging, "components"), 0o700); err != nil {
		return err
	}
	for _, provider := range providers {
		templatePath := filepath.Join(sourceSet, "providers", provider.ID, filepath.FromSlash(provider.Profile))
		data, err := readRegular(templatePath, 4*1024*1024)
		if err != nil {
			return fmt.Errorf("read component %q profile: %w", provider.ID, err)
		}
		var value component.Profile
		if err := strictjson.Decode(data, &value, true); err != nil {
			return fmt.Errorf("decode component %q: %w", provider.ID, err)
		}
		if err := renderComponent(&value, provider.ID, source); err != nil {
			return err
		}
		componentPath := filepath.Join(staging, filepath.FromSlash(componentProfilePath(provider.ID)))
		if err := writeJSON(componentPath, value); err != nil {
			return err
		}
		if err := rewriteComponentPolicy(staging, value.Files, clientsForProvider(source, provider.ID)); err != nil {
			return err
		}
	}
	return nil
}

func renderComponent(value *component.Profile, providerID string, source installation.Installation) error {
	localUsers := localUsersForProvider(source, providerID)
	approverUsers := make([]string, 0, len(source.Approvers))
	for _, approver := range source.Approvers {
		approverUsers = append(approverUsers, approver.Account)
	}
	slices.Sort(localUsers)
	slices.Sort(approverUsers)
	for index := range value.Groups {
		switch {
		case strings.HasSuffix(value.Groups[index].Name, "-agent"):
			value.Groups[index].Members = append([]string(nil), localUsers...)
		case strings.HasSuffix(value.Groups[index].Name, "-operator"):
			value.Groups[index].Members = append([]string(nil), approverUsers...)
		}
	}
	var clientDestination, clientOwner, clientGroup string
	var clientMode uint32
	var operatorDestination, operatorOwner, operatorGroup string
	var operatorMode uint32
	kept := value.Credentials[:0]
	for _, credential := range value.Credentials {
		if credential.Encoding != "client_secret_file" {
			kept = append(kept, credential)
			continue
		}
		if strings.Contains(credential.Slot, "operator") {
			operatorDestination, operatorMode, operatorOwner, operatorGroup = credential.Destination, credential.Mode, credential.Owner, credential.Group
		} else {
			clientDestination, clientMode, clientOwner, clientGroup = credential.Destination, credential.Mode, credential.Owner, credential.Group
		}
	}
	value.Credentials = kept
	if clientDestination == "" || operatorDestination == "" {
		return fmt.Errorf("component %q has no named secret store templates", providerID)
	}
	clientStore := component.SecretStore{ID: "clients", Destination: clientDestination, Mode: clientMode, Owner: clientOwner, Group: clientGroup}
	operatorStore := component.SecretStore{ID: "approvers", Destination: operatorDestination, Mode: operatorMode, Owner: operatorOwner, Group: operatorGroup}
	for _, connection := range source.Connections {
		if !slices.Contains(connection.Providers, providerID) {
			continue
		}
		clientStore.Entries = append(clientStore.Entries, component.SecretEntry{Identity: connection.ClientID, Slot: providerID + "-client-" + connection.ClientID})
	}
	for _, approver := range source.Approvers {
		operatorStore.Entries = append(operatorStore.Entries, component.SecretEntry{Identity: approver.ID, Slot: providerID + "-approver-" + approver.ID})
	}
	value.SecretStores = []component.SecretStore{clientStore, operatorStore}
	templateClient := component.Client{}
	if len(value.Clients) > 0 {
		templateClient = value.Clients[0]
	}
	value.Clients = nil
	for _, connection := range source.Connections {
		if connection.Target.Kind != installation.TargetLocalAccount || !slices.Contains(connection.Providers, providerID) {
			continue
		}
		client := templateClient
		client.AgentID = connection.ID
		client.SecretSlot = providerID + "-client-" + connection.ClientID
		value.Clients = append(value.Clients, client)
	}
	return nil
}

//nolint:cyclop // Ownership enforcement rejects every generated resource that escapes its signed envelope.
func validateOwnershipEnvelopes(root string, deployment profile.Deployment, providers []SourceProvider) error {
	envelopes := make(map[string]bundle.OwnershipEnvelope, len(providers))
	for _, provider := range providers {
		envelopes[provider.ID] = provider.Ownership
	}
	for _, componentReference := range deployment.Components {
		envelope, exists := envelopes[componentReference.ID]
		if !exists {
			return fmt.Errorf("component %q has no ownership envelope", componentReference.ID)
		}
		componentPath := filepath.Join(root, filepath.FromSlash(componentReference.Profile.Path))
		data, err := os.ReadFile(componentPath) // #nosec G304 -- validated staging path.
		if err != nil {
			return err
		}
		var value component.Profile
		if err := strictjson.Decode(data, &value, true); err != nil {
			return fmt.Errorf("recheck component %q: %w", componentReference.ID, err)
		}
		if err := checkOwnedPaths(componentReference.ID, value, envelope); err != nil {
			return err
		}
		if err := checkOwnedIdentities(componentReference.ID, value, envelope); err != nil {
			return err
		}
	}
	return nil
}

func checkOwnedPaths(id string, value component.Profile, envelope bundle.OwnershipEnvelope) error {
	paths := append([]string(nil), envelope.Paths...)
	for _, directory := range value.Directories {
		if !ownedPath(directory.Destination, paths) {
			return fmt.Errorf("component %q directory %q escapes ownership", id, directory.Destination)
		}
	}
	for _, managed := range value.Files {
		if !ownedPath(managed.Destination, paths) {
			return fmt.Errorf("component %q file %q escapes ownership", id, managed.Destination)
		}
	}
	for _, credential := range value.Credentials {
		if !ownedPath(credential.Destination, paths) {
			return fmt.Errorf("component %q credential %q escapes ownership", id, credential.Destination)
		}
	}
	for _, store := range value.SecretStores {
		if !ownedPath(store.Destination, paths) {
			return fmt.Errorf("component %q secret store %q escapes ownership", id, store.Destination)
		}
	}
	return nil
}

func checkOwnedIdentities(id string, value component.Profile, envelope bundle.OwnershipEnvelope) error {
	services := append([]string(nil), envelope.Services...)
	accounts := append([]string(nil), envelope.Accounts...)
	groups := append([]string(nil), envelope.Groups...)
	for _, service := range value.Services {
		if !slices.Contains(services, service) {
			return fmt.Errorf("component %q service %q escapes ownership", id, service)
		}
	}
	for _, account := range value.Accounts {
		if !slices.Contains(accounts, account.Name) || !slices.Contains(groups, account.Group) {
			return fmt.Errorf("component %q account %q escapes ownership", id, account.Name)
		}
	}
	for _, group := range value.Groups {
		if !slices.Contains(groups, group.Name) {
			return fmt.Errorf("component %q group %q escapes ownership", id, group.Name)
		}
	}
	return nil
}

func ownedPath(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if path == prefix || strings.HasPrefix(path, prefix+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func componentProfilePath(id string) string { return "components/" + id + ".json" }

func clientsForProvider(source installation.Installation, provider string) []string {
	var result []string
	for _, connection := range source.Connections {
		if slices.Contains(connection.Providers, provider) {
			result = append(result, connection.ClientID)
		}
	}
	slices.Sort(result)
	return result
}

func localUsersForProvider(source installation.Installation, provider string) []string {
	var result []string
	for _, connection := range source.Connections {
		if connection.Target.Kind == installation.TargetLocalAccount && slices.Contains(connection.Providers, provider) {
			result = append(result, connection.Target.Account)
		}
	}
	return result
}

func rewriteComponentPolicy(root string, files []component.ManagedFile, clients []string) error {
	paths := map[string]string{}
	for _, managed := range files {
		name := filepath.Base(filepath.FromSlash(managed.Source.Path))
		paths[name] = filepath.Join(root, filepath.FromSlash(managed.Source.Path))
		if name == "policy-manifest.json" || !strings.Contains(name, "policy") && name != "scope.json" {
			continue
		}
		if err := rewritePolicyClients(paths[name], clients); err != nil {
			return err
		}
	}
	manifestPath := paths["policy-manifest.json"]
	profilePath := paths["policy-profile.json"]
	policyPath := paths["scope.json"]
	if manifestPath == "" || profilePath == "" || policyPath == "" {
		return nil
	}
	profileData, err := os.ReadFile(profilePath) // #nosec G304 -- compiler staging path.
	if err != nil {
		return err
	}
	policyData, err := os.ReadFile(policyPath) // #nosec G304 -- compiler staging path.
	if err != nil {
		return err
	}
	manifestData, err := os.ReadFile(manifestPath) // #nosec G304 -- compiler staging path.
	if err != nil {
		return err
	}
	var manifest map[string]any
	if err := strictjson.Decode(manifestData, &manifest, true); err != nil {
		return err
	}
	manifest["profile_digest"] = contentDigest(profileData)
	manifest["policy_digest"] = contentDigest(policyData)
	return writeJSON(manifestPath, manifest)
}

func contentDigest(data []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(data))
}

// rewritePolicyClients changes only formatted clients arrays. Provider field
// ordering remains intact because some provider validators require canonical
// key order in addition to equivalent JSON values.
func rewritePolicyClients(path string, clients []string) error {
	data, err := os.ReadFile(path) // #nosec G304 -- compiler staging path.
	if err != nil {
		return err
	}
	var validated any
	if err := strictjson.Decode(data, &validated, true); err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	result := make([]string, 0, len(lines)+len(clients))
	replacements := 0
	for index := 0; index < len(lines); index++ {
		line := lines[index]
		if strings.TrimSpace(line) != `"clients": [` {
			result = append(result, line)
			continue
		}
		result = append(result, line)
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))] + "  "
		closing := index + 1
		for ; closing < len(lines); closing++ {
			trimmed := strings.TrimSpace(lines[closing])
			if trimmed == "]" || trimmed == "]," {
				break
			}
		}
		if closing == len(lines) {
			return errors.New("policy client list is not closed")
		}
		for clientIndex, client := range clients {
			encoded, marshalErr := json.Marshal(client)
			if marshalErr != nil {
				return marshalErr
			}
			suffix := ","
			if clientIndex == len(clients)-1 {
				suffix = ""
			}
			result = append(result, indent+string(encoded)+suffix)
		}
		result = append(result, lines[closing])
		index, replacements = closing, replacements+1
	}
	if replacements == 0 {
		return errors.New("managed policy contains no client list")
	}
	return os.WriteFile(path, []byte(strings.Join(result, "\n")), 0o600)
}

func readRegular(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maximum {
		return nil, errors.New("source file is unsafe")
	}
	file, err := os.Open(path) // #nosec G304 -- path is below a verified release artifact root.
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	return data, errors.Join(readErr, file.Close())
}

func writeRelative(root, relative string, data []byte, mode os.FileMode) error {
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, mode)
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func cleanAbsolute(path string) bool { return filepath.IsAbs(path) && filepath.Clean(path) == path }

func zeroDigest() string { return "sha256:" + strings.Repeat("0", 64) }
