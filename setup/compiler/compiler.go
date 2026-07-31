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
	"github.com/osolmaz/unyolo/internal/pathutil"
	"github.com/osolmaz/unyolo/internal/strictjson"
	"github.com/osolmaz/unyolo/setup/installation"
)

type Options struct {
	Installation installation.Installation
	Template     profile.Snapshot
	ArtifactRoot string
	Destination  string
}

func Compile(options Options) (profile.Snapshot, error) {
	if err := options.Installation.Validate(); err != nil {
		return profile.Snapshot{}, err
	}
	if !cleanAbsolute(options.ArtifactRoot) || !cleanAbsolute(options.Destination) ||
		pathutil.Overlap(options.Destination, options.Template.Root) || pathutil.Overlap(options.Destination, options.ArtifactRoot) {
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
	defer func() { _ = os.RemoveAll(staging) }()
	if err := copySources(options.Template, options.ArtifactRoot, staging); err != nil {
		return profile.Snapshot{}, err
	}
	deployment, err := compileDeployment(options.Installation, options.Template.Deployment)
	if err != nil {
		return profile.Snapshot{}, err
	}
	if err := renderComponents(staging, options.Installation, deployment); err != nil {
		return profile.Snapshot{}, err
	}
	if err := writeJSON(filepath.Join(staging, profile.EntryFilename), deployment); err != nil {
		return profile.Snapshot{}, err
	}
	if err := profile.Lock(staging, false); err != nil {
		return profile.Snapshot{}, err
	}
	if err := os.Rename(staging, options.Destination); err != nil {
		return profile.Snapshot{}, err
	}
	return profile.Load(options.Destination)
}

func compileDeployment(source installation.Installation, template profile.Deployment) (profile.Deployment, error) {
	digest, err := source.Digest()
	if err != nil {
		return profile.Deployment{}, err
	}
	result := template
	result.Name, result.InstallationDigest = source.Name, digest
	result.Agents = nil
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
		result.Agents = append(result.Agents, profile.Agent{ID: connection.ID, ClientID: connection.ClientID, Target: target, ComponentIDs: append([]string(nil), connection.Providers...)})
	}
	result.Operators = nil
	for _, approver := range source.Approvers {
		result.Operators = append(result.Operators, profile.Operator{ID: approver.ID, UnixUser: approver.Account})
	}
	if err := result.Validate(); err != nil {
		return profile.Deployment{}, err
	}
	return result, nil
}

func renderComponents(root string, source installation.Installation, deployment profile.Deployment) error {
	for _, selected := range deployment.Components {
		path := filepath.Join(root, filepath.FromSlash(selected.Profile.Path))
		data, err := os.ReadFile(path) // #nosec G304 -- path is a validated template reference below private staging.
		if err != nil {
			return err
		}
		var value component.Profile
		if err := strictjson.Decode(data, &value, true); err != nil {
			return fmt.Errorf("decode component %q: %w", selected.ID, err)
		}
		if err := renderComponent(&value, selected.ID, source); err != nil {
			return err
		}
		if err := writeJSON(path, value); err != nil {
			return err
		}
		if err := rewriteComponentPolicy(root, value.Files, clientsForProvider(source, selected.ID)); err != nil {
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
	profileData, err := os.ReadFile(profilePath) // #nosec G304 -- verified compiler staging path.
	if err != nil {
		return err
	}
	policyData, err := os.ReadFile(policyPath) // #nosec G304 -- verified compiler staging path.
	if err != nil {
		return err
	}
	manifestData, err := os.ReadFile(manifestPath) // #nosec G304 -- verified compiler staging path.
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

func rewritePolicyClients(path string, clients []string) error {
	data, err := os.ReadFile(path) // #nosec G304 -- validated source path below compiler staging.
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

func copySources(snapshot profile.Snapshot, artifactRoot, destination string) error {
	for _, file := range snapshot.Files {
		if err := writeRelative(destination, file.Path, file.Data, 0o600); err != nil {
			return err
		}
	}
	for _, artifact := range snapshot.Manifest.Components {
		source := filepath.Join(artifactRoot, filepath.FromSlash(artifact.Source))
		data, err := readRegular(source, 256*1024*1024)
		if err != nil {
			return fmt.Errorf("copy runtime artifact %q: %w", artifact.Name, err)
		}
		if err := writeRelative(destination, artifact.Source, data, 0o700); err != nil {
			return err
		}
	}
	return nil
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
