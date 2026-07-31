// Package sourceset validates and fingerprints one verified setup source set.
package sourceset

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxEntries   = 4096
	maxFileSize  = 512 * 1024 * 1024
	maxTotalSize = 8 * 1024 * 1024 * 1024
)

// Digest returns a deterministic digest over every directory name, file name,
// and regular-file byte in root. Symlinks and special files are rejected.
func Digest(root string) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", errors.New("source set root must be an absolute clean path")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("source set root must be a real directory")
	}
	hash := sha256.New()
	entries := 0
	var total int64
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		entries++
		if entries > maxEntries {
			return errors.New("source set contains too many entries")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == "." || strings.ContainsRune(relative, 0) {
			return errors.New("source set contains an invalid path")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("source set contains a symbolic link")
		}
		kind := byte('d')
		if info.Mode().IsRegular() {
			kind = 'f'
			if info.Size() < 0 || info.Size() > maxFileSize || total > maxTotalSize-info.Size() {
				return errors.New("source set exceeds its size bound")
			}
			total += info.Size()
		} else if !info.IsDir() {
			return errors.New("source set contains a special file")
		}
		if err := writeEntryHeader(hash, kind, relative, info.Size()); err != nil {
			return err
		}
		if kind == 'f' {
			file, err := os.Open(path) // #nosec G304 -- WalkDir supplies a child of the validated source root.
			if err != nil {
				return err
			}
			written, copyErr := io.Copy(hash, io.LimitReader(file, maxFileSize+1))
			closeErr := file.Close()
			if copyErr != nil || closeErr != nil {
				return errors.Join(copyErr, closeErr)
			}
			if written != info.Size() {
				return errors.New("source set file changed while hashing")
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", hash.Sum(nil)), nil
}

func writeEntryHeader(writer io.Writer, kind byte, path string, size int64) error {
	if _, err := writer.Write([]byte{kind}); err != nil {
		return err
	}
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(len(path)))
	if _, err := writer.Write(encoded[:]); err != nil {
		return err
	}
	if _, err := io.WriteString(writer, path); err != nil {
		return err
	}
	binary.BigEndian.PutUint64(encoded[:], uint64(size))
	_, err := writer.Write(encoded[:])
	return err
}
