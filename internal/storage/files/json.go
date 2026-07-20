// Package store provides small durable local storage helpers.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
)

// ReadJSON reads JSON from path into out. Missing files decode as zero values.
func ReadJSON(path string, out any) error {
	data, err := os.ReadFile(path) // #nosec G304 -- broker state paths are operator configured.
	if errors.Is(err, os.ErrNotExist) {
		resetOutput(out)
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) == 0 {
		resetOutput(out)
		return nil
	}
	resetOutput(out)
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func resetOutput(out any) {
	value := reflect.ValueOf(out)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return
	}
	elem := value.Elem()
	if elem.CanSet() {
		elem.Set(reflect.Zero(elem.Type()))
	}
}

// WriteJSONAtomic writes a stable JSON document using rename-based replacement.
func WriteJSONAtomic(path string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	data = append(data, '\n')
	return WriteFileAtomic(path, data, mode)
}

// WriteFileAtomic writes data to path using a temporary file and rename.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create state directory %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file for %s: %w", path, err)
	}
	tmpName, err := writeTempFile(tmp, path, data, mode)
	if err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return syncDirectory(dir, path)
}

func writeTempFile(tmp *os.File, path string, data []byte, mode os.FileMode) (string, error) {
	tmpName := tmp.Name()
	if err := writeTempFileContent(tmp, path, data, mode); err != nil {
		_ = os.Remove(tmpName)
		return "", err
	}
	return tmpName, nil
}

func writeTempFileContent(tmp *os.File, path string, data []byte, mode os.FileMode) error {
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file for %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file for %s: %w", path, err)
	}
	return syncAndCloseTempFile(tmp, path)
}

func syncAndCloseTempFile(tmp *os.File, path string) error {
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file for %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file for %s: %w", path, err)
	}
	return nil
}

func syncDirectory(dir string, path string) error {
	handle, err := os.Open(dir) // #nosec G304 -- broker state directories are operator configured.
	if err != nil {
		return fmt.Errorf("open state directory for %s: %w", path, err)
	}
	if err := handle.Sync(); err != nil {
		_ = handle.Close()
		return fmt.Errorf("sync state directory for %s: %w", path, err)
	}
	if err := handle.Close(); err != nil {
		return fmt.Errorf("close state directory for %s: %w", path, err)
	}
	return nil
}
