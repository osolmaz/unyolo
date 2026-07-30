package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/osolmaz/unyolo/internal/pathutil"
)

// MaterializeReleaseTemplate constructs an operator-owned deployment pack from
// one verified release template and the release's shared runtime artifacts.
// The template remains immutable; the generated pack receives the requested
// deployment and operator identities before it is locked and verified.
//
//nolint:cyclop // Template hydration, identity binding, locking, verification, and atomic publication form one boundary.
func MaterializeReleaseTemplate(snapshot Snapshot, artifactRoot, destination, deploymentName, operator string, selected []string) (string, error) {
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination ||
		pathutil.Overlap(destination, snapshot.Root) || pathutil.Overlap(destination, artifactRoot) {
		return "", errors.New("deployment template destination is invalid")
	}
	if !filepath.IsAbs(artifactRoot) || filepath.Clean(artifactRoot) != artifactRoot {
		return "", errors.New("deployment template artifact root is invalid")
	}
	artifactInfo, err := os.Lstat(artifactRoot)
	if err != nil || !artifactInfo.IsDir() || artifactInfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("deployment template artifact root must be a real directory")
	}
	deployment, err := selectedDeployment(snapshot.Deployment, deploymentName, selected)
	if err != nil {
		return "", err
	}
	if !validUnixName(operator) || len(deployment.Operators) != 1 {
		return "", errors.New("deployment template requires one valid invoking operator")
	}
	deployment.Operators[0].UnixUser = operator

	parent, staging, err := createMaterializationStaging(destination)
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	for _, file := range snapshot.Files {
		if file.Path == EntryFilename {
			continue
		}
		if err := copyMaterializedFile(snapshot.Root, staging, file.Path); err != nil {
			return "", err
		}
	}
	for _, component := range snapshot.Manifest.Components {
		if err := copyMaterializedFile(artifactRoot, staging, component.Source); err != nil {
			return "", fmt.Errorf("hydrate runtime artifact %q: %w", component.Name, err)
		}
	}
	for _, component := range deployment.Components {
		if err := bindTemplateIdentities(filepath.Join(staging, filepath.FromSlash(component.Profile.Path)), operator); err != nil {
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
	return finalizeMaterializedPack(staging, destination, parent, false)
}

func bindTemplateIdentities(path, operator string) error {
	data, err := os.ReadFile(path) // #nosec G304 -- selected profile path below private materialization staging.
	if err != nil {
		return err
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("decode deployment template identities: %w", err)
	}
	if !replaceTemplateIdentity(value, operator) {
		return nil
	}
	updated, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(updated, '\n'), 0o600)
}

//nolint:cyclop // Recursive JSON traversal handles the two bounded identity placeholders explicitly.
func replaceTemplateIdentity(value any, operator string) bool {
	changed := false
	switch typed := value.(type) {
	case []any:
		for index, child := range typed {
			if text, ok := child.(string); ok {
				if replacement, found := templateIdentity(text, operator); found {
					typed[index], changed = replacement, true
				}
				continue
			}
			changed = replaceTemplateIdentity(child, operator) || changed
		}
	case map[string]any:
		for key, child := range typed {
			if text, ok := child.(string); ok {
				if replacement, found := templateIdentity(text, operator); found {
					typed[key], changed = replacement, true
				}
				continue
			}
			changed = replaceTemplateIdentity(child, operator) || changed
		}
	}
	return changed
}

func templateIdentity(value, operator string) (string, bool) {
	switch value {
	case "$UNYOLO_OPERATOR":
		return operator, true
	case "$UNYOLO_AGENT":
		return "unyolo-agent", true
	default:
		return "", false
	}
}
