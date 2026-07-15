package policypreset

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type Output struct {
	Path string
	Data []byte
	Mode os.FileMode
}

type ExistingOutputError struct{ Path string }

func (err *ExistingOutputError) Error() string {
	return fmt.Sprintf("refusing to replace existing file %s", err.Path)
}

// WriteOutputs atomically creates or replaces a complete policy artifact set.
// Each staged file is synchronized before commit and each touched directory is
// synchronized before successful return.
func WriteOutputs(outputs []Output, replace bool) error {
	if err := validateOutputs(outputs); err != nil {
		return err
	}
	staged, err := stageOutputs(outputs)
	if err != nil {
		return err
	}
	defer cleanupStaged(staged)
	if replace {
		err = replaceOutputs(staged)
	} else {
		err = createOutputs(staged)
	}
	if err != nil {
		return errors.Join(err, rollbackOutputs(staged))
	}
	if err := syncOutputDirectories(staged); err != nil {
		return errors.Join(err, rollbackOutputs(staged))
	}
	removeBackups(staged)
	return nil
}

type stagedOutput struct {
	output    Output
	temporary string
	backup    string
	info      os.FileInfo
	committed bool
}

func validateOutputs(outputs []Output) error {
	if len(outputs) == 0 {
		return errors.New("policy artifact outputs must not be empty")
	}
	seen := make(map[string]bool, len(outputs))
	for index := range outputs {
		output := &outputs[index]
		if err := validateOutput(output, seen); err != nil {
			return err
		}
	}
	return nil
}

func validateOutput(output *Output, seen map[string]bool) error {
	if output.Path == "" {
		return errors.New("policy artifact output path must not be empty")
	}
	path, err := normalizeOutputPath(output.Path)
	if err != nil {
		return err
	}
	if seen[path] {
		return fmt.Errorf("policy artifact output paths must be distinct: %s", path)
	}
	seen[path] = true
	output.Path = path
	if output.Mode == 0 {
		output.Mode = 0o644
	}
	if output.Mode.Perm() != output.Mode || output.Mode&0o022 != 0 {
		return fmt.Errorf("policy artifact output %s has unsafe mode %04o", path, output.Mode)
	}
	return nil
}

func normalizeOutputPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve policy output %s: %w", path, err)
	}
	resolved, err := resolveExistingPathPrefix(filepath.Clean(absolute))
	if err != nil {
		return "", fmt.Errorf("resolve policy output %s: %w", path, err)
	}
	return resolved, nil
}

func resolveExistingPathPrefix(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	parent := filepath.Dir(path)
	if parent == path {
		return path, nil
	}
	resolvedParent, err := resolveExistingPathPrefix(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolvedParent, filepath.Base(path)), nil
}

func stageOutputs(outputs []Output) ([]*stagedOutput, error) {
	staged := make([]*stagedOutput, 0, len(outputs))
	for _, output := range outputs {
		artifact, err := stageOutput(output)
		if err != nil {
			cleanupStaged(staged)
			return nil, err
		}
		staged = append(staged, artifact)
	}
	return staged, nil
}

func stageOutput(output Output) (*stagedOutput, error) {
	directory := filepath.Dir(output.Path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create policy output directory %s: %w", directory, err)
	}
	file, err := os.CreateTemp(directory, "."+filepath.Base(output.Path)+".*.stage")
	if err != nil {
		return nil, fmt.Errorf("stage policy output %s: %w", output.Path, err)
	}
	temporary := file.Name()
	if err := writeStagedOutput(file, output); err != nil {
		_ = os.Remove(temporary)
		return nil, err
	}
	info, err := os.Stat(temporary)
	if err != nil {
		_ = os.Remove(temporary)
		return nil, fmt.Errorf("inspect staged policy output %s: %w", output.Path, err)
	}
	return &stagedOutput{output: output, temporary: temporary, info: info}, nil
}

func writeStagedOutput(file *os.File, output Output) error {
	if err := populateStagedOutput(file, output); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close staged policy output %s: %w", output.Path, err)
	}
	return nil
}

func populateStagedOutput(file *os.File, output Output) error {
	if err := file.Chmod(output.Mode); err != nil {
		return fmt.Errorf("chmod staged policy output %s: %w", output.Path, err)
	}
	if _, err := file.Write(output.Data); err != nil {
		return fmt.Errorf("write staged policy output %s: %w", output.Path, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync staged policy output %s: %w", output.Path, err)
	}
	return nil
}

func createOutputs(staged []*stagedOutput) error {
	for _, artifact := range staged {
		if err := os.Link(artifact.temporary, artifact.output.Path); err != nil {
			if errors.Is(err, os.ErrExist) {
				return &ExistingOutputError{Path: artifact.output.Path}
			}
			return fmt.Errorf("create policy output %s: %w", artifact.output.Path, err)
		}
		artifact.committed = true
	}
	return nil
}

func replaceOutputs(staged []*stagedOutput) error {
	for _, artifact := range staged {
		if err := backupOutput(artifact); err != nil {
			return err
		}
	}
	for _, artifact := range staged {
		if err := os.Rename(artifact.temporary, artifact.output.Path); err != nil {
			return fmt.Errorf("replace policy output %s: %w", artifact.output.Path, err)
		}
		artifact.temporary = ""
		artifact.committed = true
	}
	return nil
}

func backupOutput(artifact *stagedOutput) error {
	info, err := os.Lstat(artifact.output.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect policy output %s: %w", artifact.output.Path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("refusing to replace policy output directory %s", artifact.output.Path)
	}
	backup, err := unusedBackupPath(artifact.output.Path)
	if err != nil {
		return err
	}
	if err := os.Link(artifact.output.Path, backup); err != nil {
		return fmt.Errorf("backup policy output %s: %w", artifact.output.Path, err)
	}
	artifact.backup = backup
	return nil
}

func unusedBackupPath(path string) (string, error) {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.backup")
	if err != nil {
		return "", fmt.Errorf("reserve backup for policy output %s: %w", path, err)
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	if err := os.Remove(name); err != nil {
		return "", err
	}
	return name, nil
}

func rollbackOutputs(staged []*stagedOutput) error {
	var rollbackErrors []error
	for index := len(staged) - 1; index >= 0; index-- {
		artifact := staged[index]
		if err := rollbackOutput(artifact); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
	}
	if err := syncOutputDirectories(staged); err != nil {
		rollbackErrors = append(rollbackErrors, err)
	}
	return errors.Join(rollbackErrors...)
}

func rollbackOutput(artifact *stagedOutput) error {
	if artifact.committed {
		if err := removeCommittedOutput(artifact); err != nil {
			return err
		}
	}
	return restoreBackupOutput(artifact)
}

func restoreBackupOutput(artifact *stagedOutput) error {
	if artifact.backup == "" {
		return nil
	}
	if err := os.Rename(artifact.backup, artifact.output.Path); err != nil {
		return fmt.Errorf("restore policy output %s: %w", artifact.output.Path, err)
	}
	artifact.backup = ""
	return nil
}

func removeCommittedOutput(artifact *stagedOutput) error {
	info, err := os.Stat(artifact.output.Path)
	if err != nil {
		return fmt.Errorf("inspect committed policy output %s: %w", artifact.output.Path, err)
	}
	if !os.SameFile(info, artifact.info) {
		return fmt.Errorf("refusing to roll back policy output %s changed by another process", artifact.output.Path)
	}
	if err := os.Remove(artifact.output.Path); err != nil {
		return fmt.Errorf("remove committed policy output %s: %w", artifact.output.Path, err)
	}
	artifact.committed = false
	return nil
}

func syncOutputDirectories(staged []*stagedOutput) error {
	seen := make(map[string]bool, len(staged))
	for _, artifact := range staged {
		directory := filepath.Dir(artifact.output.Path)
		if seen[directory] {
			continue
		}
		seen[directory] = true
		handle, err := os.Open(directory) // #nosec G304 -- validated operator-selected output directory.
		if err != nil {
			return fmt.Errorf("open policy output directory %s: %w", directory, err)
		}
		if err := handle.Sync(); err != nil {
			_ = handle.Close()
			return fmt.Errorf("sync policy output directory %s: %w", directory, err)
		}
		if err := handle.Close(); err != nil {
			return fmt.Errorf("close policy output directory %s: %w", directory, err)
		}
	}
	return nil
}

func removeBackups(staged []*stagedOutput) {
	for _, artifact := range staged {
		if artifact.backup != "" {
			_ = os.Remove(artifact.backup)
			artifact.backup = ""
		}
	}
}

func cleanupStaged(staged []*stagedOutput) {
	for _, artifact := range staged {
		if artifact.temporary != "" {
			_ = os.Remove(artifact.temporary)
		}
		if artifact.backup != "" {
			_ = os.Remove(artifact.backup)
		}
	}
}
