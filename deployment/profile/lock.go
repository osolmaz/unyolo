package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/osolmaz/brokerkit/internal/strictjson"
)

// ErrLockOutOfDate means profile lock --check found stale canonical bytes.
var ErrLockOutOfDate = errors.New("deployment profile lock is out of date")

// Lock recalculates referenced-file digests and canonicalizes the entry file.
// In check mode it performs no writes.
//
//nolint:cyclop // Locking traverses and updates every bounded reference in one atomic profile operation.
func Lock(root string, check bool) error {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	if err := inspectAbsolutePath(absolute); err != nil {
		return err
	}
	packRoot, err := os.OpenRoot(absolute)
	if err != nil {
		return fmt.Errorf("open deployment pack: %w", err)
	}
	defer func() { _ = packRoot.Close() }()
	entry, err := readFile(packRoot, EntryFilename, MaxEntryBytes)
	if err != nil {
		return err
	}
	var deployment Deployment
	if err := strictjson.Decode(entry, &deployment, true); err != nil {
		return fmt.Errorf("decode %s: %w", EntryFilename, err)
	}
	if err := deployment.Validate(); err != nil {
		return err
	}

	changed := false
	profileRefs := make([]*Reference, 0, len(deployment.Components)+len(deployment.Integrations))
	for index := range deployment.Components {
		profileRefs = append(profileRefs, &deployment.Components[index].Profile)
	}
	for index := range deployment.Integrations {
		profileRefs = append(profileRefs, &deployment.Integrations[index].Profile)
	}
	for _, reference := range profileRefs {
		profileChanged, lockErr := lockNestedReferences(packRoot, reference.Path, check)
		if lockErr != nil {
			return lockErr
		}
		changed = changed || profileChanged
		actual, digestErr := digestPath(packRoot, reference.Path)
		if digestErr != nil {
			return digestErr
		}
		if reference.SHA256 != actual {
			reference.SHA256 = actual
			changed = true
		}
	}
	for _, reference := range []*Reference{
		&deployment.Runtime.Manifest,
		&deployment.Runtime.Signature,
		&deployment.Runtime.PublicKey,
	} {
		actual, digestErr := digestPath(packRoot, reference.Path)
		if digestErr != nil {
			return digestErr
		}
		if reference.SHA256 != actual {
			reference.SHA256 = actual
			changed = true
		}
	}
	canonical, err := canonicalIndented(deployment)
	if err != nil {
		return err
	}
	if !bytes.Equal(entry, canonical) {
		changed = true
	}
	if check && changed {
		return ErrLockOutOfDate
	}
	if changed {
		if err := writeAtomic(absolute, EntryFilename, canonical, 0o600); err != nil {
			return err
		}
	}
	_, err = Load(absolute)
	return err
}

func lockNestedReferences(root *os.Root, path string, check bool) (bool, error) {
	data, err := readFile(root, path, MaxReferenced)
	if err != nil {
		return false, fmt.Errorf("read component profile %q: %w", path, err)
	}
	if err := strictjson.RejectDuplicateKeys(data); err != nil {
		return false, fmt.Errorf("decode component profile %q: %w", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return false, fmt.Errorf("decode component profile %q: %w", path, err)
	}
	changed, err := lockValue(root, value)
	if err != nil {
		return false, fmt.Errorf("lock component profile %q: %w", path, err)
	}
	if !changed {
		return false, nil
	}
	updated, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return false, err
	}
	updated = append(updated, '\n')
	if check {
		return true, nil
	}
	return true, writeAtomic(root.Name(), path, updated, 0o600)
}

//nolint:cyclop // Recursive JSON traversal handles the closed object and array shapes explicitly.
func lockValue(root *os.Root, value any) (bool, error) {
	switch typed := value.(type) {
	case []any:
		changed := false
		for _, child := range typed {
			childChanged, err := lockValue(root, child)
			if err != nil {
				return false, err
			}
			changed = changed || childChanged
		}
		return changed, nil
	case map[string]any:
		if pathValue, pathOK := typed["path"].(string); pathOK {
			if digestValue, digestOK := typed["sha256"].(string); digestOK && len(typed) == 2 {
				if err := validateRelative(pathValue); err != nil {
					return false, err
				}
				actual, err := digestPath(root, pathValue)
				if err != nil {
					return false, err
				}
				if digestValue != actual {
					typed["sha256"] = actual
					return true, nil
				}
				return false, nil
			}
		}
		changed := false
		for _, child := range typed {
			childChanged, err := lockValue(root, child)
			if err != nil {
				return false, err
			}
			changed = changed || childChanged
		}
		return changed, nil
	default:
		return false, nil
	}
}

func digestPath(root *os.Root, path string) (string, error) {
	data, err := readFile(root, path, MaxReferenced)
	if err != nil {
		return "", fmt.Errorf("digest referenced file %q: %w", path, err)
	}
	return digest(data), nil
}

func canonicalIndented(value Deployment) ([]byte, error) {
	slices.SortFunc(value.Agents, func(a, b Agent) int { return compare(a.ID, b.ID) })
	slices.SortFunc(value.Operators, func(a, b Operator) int { return compare(a.ID, b.ID) })
	slices.SortFunc(value.Components, func(a, b Component) int { return compare(a.ID, b.ID) })
	slices.SortFunc(value.Integrations, func(a, b Integration) int { return compare(a.ID, b.ID) })
	for index := range value.Agents {
		slices.Sort(value.Agents[index].ComponentIDs)
	}
	data, err := json.MarshalIndent(value, "", "  ")
	return append(data, '\n'), err
}

func compare(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func writeAtomic(root, relative string, data []byte, mode os.FileMode) error {
	path := filepath.Join(root, filepath.FromSlash(relative))
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".brokerkit-profile-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer func() { _ = os.Remove(temporary) }()
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	dir, err := os.Open(directory) // #nosec G304 -- directory is the validated deployment pack root.
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
