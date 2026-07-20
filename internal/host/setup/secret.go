package setup

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/osolmaz/brokerkit/auth"
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
		file, err := os.Open(source.File) // #nosec G304 -- operator configured setup input.
		if err != nil {
			return "", fmt.Errorf("read secret file: %w", err)
		}
		secret, readErr := readSecret(file)
		closeErr := file.Close()
		if readErr != nil {
			return "", readErr
		}
		if closeErr != nil {
			return "", fmt.Errorf("close secret file: %w", closeErr)
		}
		return secret, nil
	case source.Stdin:
		return readSecret(stdin)
	default:
		return GenerateSecret()
	}
}

func readSecret(reader io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxSecretInputBytes+1))
	if err != nil {
		return "", fmt.Errorf("read secret input: %w", err)
	}
	if len(data) > maxSecretInputBytes {
		return "", errors.New("secret input exceeds 4096 bytes")
	}
	return validateSecret(string(data))
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
	if len([]byte(secret)) < auth.MinimumSecretBytes {
		return "", fmt.Errorf("secret must be at least %d bytes", auth.MinimumSecretBytes)
	}
	if strings.ContainsAny(secret, "\r\n\x00") {
		return "", errors.New("secret must be one nonempty line")
	}
	return secret, nil
}
