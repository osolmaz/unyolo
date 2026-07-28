// Package keyfile loads or creates private symmetric keys for local stores.
package keyfile

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"

	"github.com/osolmaz/unyolo/internal/securefile"
)

type Encoding int

const (
	Raw Encoding = iota
	Base64
)

// LoadOrCreate reads an owner-only key or creates one atomically.
func LoadOrCreate(path string, size int, noun string, encoding Encoding) ([]byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- caller owns the fixed store path.
	if err == nil {
		return decodeExisting(path, data, size, noun, encoding)
	}
	if !os.IsNotExist(err) {
		return nil, errors.New("read " + noun + " key")
	}
	return create(path, size, noun, encoding)
}

// LoadExisting reads a private key without creating one when it is absent.
func LoadExisting(path string, size int, noun string, encoding Encoding) ([]byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- caller owns the fixed store path.
	if err != nil {
		return nil, errors.New("read " + noun + " key")
	}
	return decodeExisting(path, data, size, noun, encoding)
}

func decodeExisting(path string, data []byte, size int, noun string, encoding Encoding) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New(noun + " key is invalid")
	}
	decoded, err := decode(data, encoding)
	if err != nil || len(decoded) != size {
		return nil, errors.New(noun + " key is invalid")
	}
	return decoded, nil
}

func create(path string, size int, noun string, encoding Encoding) ([]byte, error) {
	key := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, errors.New("generate " + noun + " key")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- fixed installation-owned key path.
	if err != nil {
		return nil, errors.New("create " + noun + " key")
	}
	if err := securefile.WriteAndSync(file, encode(key, encoding), noun+" key"); err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	return key, nil
}

func encode(value []byte, encoding Encoding) []byte {
	if encoding == Base64 {
		return []byte(base64.RawStdEncoding.EncodeToString(value))
	}
	return value
}

func decode(value []byte, encoding Encoding) ([]byte, error) {
	if encoding == Base64 {
		return base64.RawStdEncoding.DecodeString(string(value))
	}
	return value, nil
}
