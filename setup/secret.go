package setup

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	generatedSecretBytes = 32
	maxSecretInputBytes  = 4096
)

// SecretInput describes one file, stdin, or generated secret source.
type SecretInput struct {
	File  string
	Stdin bool
}

// ResolveSecret reads or generates a secret without printing it.
func ResolveSecret(source SecretInput, stdin io.Reader) (string, error) {
	switch {
	case source.File != "" && source.Stdin:
		return "", errors.New("secret file and stdin inputs are mutually exclusive")
	case source.File != "":
		data, err := os.ReadFile(source.File) // #nosec G304 -- operator configured setup input.
		if err != nil {
			return "", fmt.Errorf("read secret file: %w", err)
		}
		return validateSecret(string(data))
	case source.Stdin:
		data, err := io.ReadAll(io.LimitReader(stdin, maxSecretInputBytes+1))
		if err != nil {
			return "", fmt.Errorf("read secret from stdin: %w", err)
		}
		if len(data) > maxSecretInputBytes {
			return "", errors.New("secret input exceeds 4096 bytes")
		}
		return validateSecret(string(data))
	default:
		return GenerateSecret()
	}
}

// GenerateSecret returns a 256-bit random secret encoded as lowercase hex.
func GenerateSecret() (string, error) {
	data := make([]byte, generatedSecretBytes)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("generate shared secret: %w", err)
	}
	return hex.EncodeToString(data), nil
}

func validateSecret(value string) (string, error) {
	secret := strings.TrimSpace(value)
	if len(secret) < 32 {
		return "", errors.New("secret must be at least 32 characters")
	}
	if strings.ContainsAny(secret, "\r\n\x00") {
		return "", errors.New("secret must be one nonempty line")
	}
	return secret, nil
}
