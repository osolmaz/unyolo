package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/osolmaz/unyolo/internal/pathutil"
)

// MaterializeComponents copies a verified kit while retaining only the selected deployment components.
//
//nolint:cyclop // Validation, filtered copy, locking, reuse, and atomic publication share one boundary.
func MaterializeComponents(snapshot Snapshot, destination string, deploymentName string, selected []string) (string, error) {
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination || pathutil.Overlap(destination, snapshot.Root) {
		return "", errors.New("deployment materialization destination is invalid")
	}
	deployment, err := selectedDeployment(snapshot.Deployment, deploymentName, selected)
	if err != nil {
		return "", err
	}
	parent := filepath.Dir(destination)
	if err := ensureMaterializationParent(parent); err != nil {
		return "", err
	}
	staging, err := os.MkdirTemp(parent, ".unyolo-deployment-*")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	if err := os.Chmod(staging, 0o700); err != nil { // #nosec G302 -- owner-only deployment staging.
		return "", err
	}
	paths, err := materializationPaths(snapshot)
	if err != nil {
		return "", err
	}
	for _, relative := range paths {
		if relative == EntryFilename {
			continue
		}
		if err := copyMaterializedFile(snapshot.Root, staging, relative); err != nil {
			return "", err
		}
	}
	data, err := json.MarshalIndent(deployment, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(staging, EntryFilename), append(data, '\n'), 0o600); err != nil {
		return "", err
	}
	if err := Lock(staging, true); err != nil {
		return "", fmt.Errorf("verify selected deployment lock: %w", err)
	}
	candidate, err := Load(staging)
	if err != nil {
		return "", fmt.Errorf("verify selected deployment: %w", err)
	}
	for _, component := range candidate.Manifest.Components {
		if _, err := candidate.VerifyArtifact(component.Source, component.SHA256); err != nil {
			return "", fmt.Errorf("verify selected runtime artifact: %w", err)
		}
	}
	if _, statErr := os.Lstat(destination); statErr == nil {
		existing, loadErr := Load(destination)
		if loadErr != nil {
			return "", fmt.Errorf("inspect deployment destination: %w", loadErr)
		}
		if existing.Digest == candidate.Digest {
			return destination, nil
		}
		return "", errors.New("deployment destination contains a different locked pack")
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", fmt.Errorf("inspect deployment destination: %w", statErr)
	}
	if err := os.Rename(staging, destination); err != nil {
		return "", err
	}
	return destination, syncMaterializationDirectory(parent)
}

//nolint:cyclop // Selection validates and filters components, agents, bindings, and integrations together.
func selectedDeployment(deployment Deployment, deploymentName string, selected []string) (Deployment, error) {
	if len(selected) == 0 || len(selected) > MaxComponents {
		return Deployment{}, errors.New("at least one bounded provider selection is required")
	}
	wanted := map[string]bool{}
	for _, id := range selected {
		if wanted[id] {
			return Deployment{}, fmt.Errorf("provider %q is selected more than once", id)
		}
		wanted[id] = true
	}
	if !validName(deploymentName) {
		return Deployment{}, errors.New("selected deployment name is invalid")
	}
	result := deployment
	result.Name = deploymentName
	result.Components = nil
	available := map[string]bool{}
	for _, component := range deployment.Components {
		available[component.ID] = true
		if wanted[component.ID] {
			result.Components = append(result.Components, component)
		}
	}
	for id := range wanted {
		if !available[id] {
			return Deployment{}, fmt.Errorf("selected provider %q is absent from the deployment kit", id)
		}
	}
	result.Agents = nil
	retainedAgents := map[string]bool{}
	for _, agent := range deployment.Agents {
		bindings := make([]string, 0, len(agent.ComponentIDs))
		for _, id := range agent.ComponentIDs {
			if wanted[id] {
				bindings = append(bindings, id)
			}
		}
		if len(bindings) == 0 {
			continue
		}
		agent.ComponentIDs = slices.Clone(bindings)
		result.Agents = append(result.Agents, agent)
		retainedAgents[agent.ID] = true
	}
	if len(result.Agents) == 0 {
		return Deployment{}, errors.New("selected providers leave no agent binding")
	}
	result.Integrations = nil
	for _, integration := range deployment.Integrations {
		if retainedAgents[integration.AgentID] {
			result.Integrations = append(result.Integrations, integration)
		}
	}
	return result, nil
}
