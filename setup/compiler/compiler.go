// Package compiler deterministically renders a guided installation into one locked host deployment.
package compiler

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/osolmaz/unyolo/deployment/api"
	"github.com/osolmaz/unyolo/deployment/component"
	"github.com/osolmaz/unyolo/deployment/profile"
	adapterruntime "github.com/osolmaz/unyolo/deployment/runtime"
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
	APIVersion      string                   `json:"api_version"`
	ID              string                   `json:"id"`
	Components      []string                 `json:"components"`
	Ownership       bundle.OwnershipEnvelope `json:"ownership"`
	Profile         string                   `json:"profile"`
	Files           []string                 `json:"files,omitempty"`
	RenderArguments []string                 `json:"render_arguments"`
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
	if err := copyRuntimeArtifacts(options.SourceSet, staging, manifest, selectedProviders); err != nil {
		return profile.Snapshot{}, err
	}
	if err := renderProviderComponents(options.SourceSet, staging, options.Installation, manifest, selectedProviders); err != nil {
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
		if descriptor.APIVersion != SourceProviderAPIVersion || descriptor.ID != entry.Name() ||
			len(descriptor.RenderArguments) == 0 || len(descriptor.RenderArguments) > 8 {
			return nil, fmt.Errorf("provider source %q identity is invalid", entry.Name())
		}
		for _, argument := range descriptor.RenderArguments {
			if argument == "" || len(argument) > 4096 || strings.ContainsRune(argument, 0) {
				return nil, fmt.Errorf("provider source %q render command is invalid", entry.Name())
			}
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
			Metadata: &profile.Reference{Path: componentMetadataPath(provider.ID), SHA256: zeroDigest()},
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

func renderProviderComponents(sourceSet, staging string, source installation.Installation, manifest bundle.Manifest, providers []SourceProvider) error {
	if err := os.MkdirAll(filepath.Join(staging, "components"), 0o700); err != nil {
		return err
	}
	for _, provider := range providers {
		request, err := providerRenderRequest(sourceSet, source, manifest, provider)
		if err != nil {
			return err
		}
		response, err := runProviderRenderer(sourceSet, manifest, provider, request)
		if err != nil {
			return fmt.Errorf("render component %q: %w", provider.ID, err)
		}
		if err := writeRenderedProvider(staging, provider, response); err != nil {
			return err
		}
	}
	return nil
}

func providerRenderRequest(sourceSet string, source installation.Installation, manifest bundle.Manifest, provider SourceProvider) (api.RenderRequest, error) {
	templatePath := filepath.Join(sourceSet, "providers", provider.ID, filepath.FromSlash(provider.Profile))
	profileTemplate, err := readRegular(templatePath, 4*1024*1024)
	if err != nil {
		return api.RenderRequest{}, fmt.Errorf("read component %q profile: %w", provider.ID, err)
	}
	request := api.RenderRequest{
		APIVersion: api.RenderAPIVersion, ComponentID: provider.ID,
		OperatingSystem: manifest.OperatingSystem, Architecture: manifest.Architecture,
		Profile: profileTemplate,
	}
	capabilityData, err := json.Marshal(manifest.SetupCapabilities)
	if err != nil {
		return api.RenderRequest{}, err
	}
	request.CapabilityDigest = contentDigest(capabilityData)
	for _, approver := range source.Approvers {
		request.Approvers = append(request.Approvers, api.RenderApprover{ID: approver.ID, Account: approver.Account})
	}
	integrations := map[string]bool{}
	for _, connection := range source.Connections {
		rendered := api.RenderConnection{
			ID: connection.ID, ClientID: connection.ClientID, Providers: append([]string(nil), connection.Providers...),
			TargetKind: string(connection.Target.Kind), Isolation: connection.Target.Isolation,
			UnixUser: connection.Target.Account, Home: connection.Target.Home,
			Container: connection.Target.Service, RemoteName: connection.Target.RemoteName,
		}
		request.Connections = append(request.Connections, rendered)
		for _, integration := range connection.Integrations {
			integrations[integration] = true
		}
	}
	for integration := range integrations {
		request.Integrations = append(request.Integrations, integration)
	}
	slices.Sort(request.Integrations)
	files := append([]string(nil), provider.Files...)
	slices.Sort(files)
	for _, relative := range files {
		data, err := readRegular(filepath.Join(sourceSet, "providers", provider.ID, filepath.FromSlash(relative)), api.MaxMessageBytes)
		if err != nil {
			return api.RenderRequest{}, fmt.Errorf("read component %q asset %q: %w", provider.ID, relative, err)
		}
		request.Files = append(request.Files, api.RenderFile{Path: relative, SHA256: contentDigest(data), Data: data})
	}
	return request, request.Validate()
}

func runProviderRenderer(sourceSet string, manifest bundle.Manifest, provider SourceProvider, request api.RenderRequest) (api.RenderResponse, error) {
	var runtimeComponent *bundle.Component
	for index := range manifest.Components {
		if manifest.Components[index].Name == provider.ID {
			runtimeComponent = &manifest.Components[index]
			break
		}
	}
	if runtimeComponent == nil || runtimeComponent.Setup == nil {
		return api.RenderResponse{}, errors.New("provider has no signed setup adapter")
	}
	executable := filepath.Join(sourceSet, filepath.FromSlash(runtimeComponent.Source))
	info, err := os.Lstat(executable)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
		return api.RenderResponse{}, errors.New("provider renderer executable is unsafe")
	}
	return (adapterruntime.Runner{}).RunRender(context.Background(), adapterruntime.Command{
		Executable: executable, Arguments: append([]string(nil), provider.RenderArguments...),
	}, request)
}

func writeRenderedProvider(staging string, provider SourceProvider, response api.RenderResponse) error {
	expected := make(map[string]bool, len(provider.Files))
	for _, path := range provider.Files {
		expected[path] = true
	}
	if len(response.Files) != len(expected) {
		return fmt.Errorf("component %q renderer returned an incomplete file set", provider.ID)
	}
	for _, file := range response.Files {
		if !expected[file.Path] {
			return fmt.Errorf("component %q renderer returned undeclared file %q", provider.ID, file.Path)
		}
		delete(expected, file.Path)
		if err := writeRelative(staging, file.Path, file.Data, 0o600); err != nil {
			return err
		}
	}
	if len(expected) != 0 {
		return fmt.Errorf("component %q renderer omitted declared files", provider.ID)
	}
	componentPath := filepath.Join(staging, filepath.FromSlash(componentProfilePath(provider.ID)))
	if err := os.WriteFile(componentPath, response.Profile, 0o600); err != nil {
		return err
	}
	metadata := response.Metadata()
	if err := metadata.Validate(); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(staging, filepath.FromSlash(componentMetadataPath(provider.ID))), metadata); err != nil {
		return err
	}
	var rendered component.Profile
	if err := strictjson.Decode(response.Profile, &rendered, true); err != nil {
		return fmt.Errorf("decode rendered component %q: %w", provider.ID, err)
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

func componentProfilePath(id string) string  { return "components/" + id + ".json" }
func componentMetadataPath(id string) string { return "components/" + id + ".render.json" }

func contentDigest(data []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(data))
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
