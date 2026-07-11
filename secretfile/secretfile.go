// Package secretfile reads and renders deterministic named-secret files.
package secretfile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
)

const maxBytes = 1024 * 1024

var identityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

// Parse reads `name = secret` records from path.
func Parse(path string) (map[string]string, error) {
	file, err := os.Open(path) // #nosec G304 -- operator-configured credential path.
	if err != nil {
		return nil, fmt.Errorf("open named secrets: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	closeErr := file.Close()
	if err != nil {
		return nil, fmt.Errorf("read named secrets: %w", err)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close named secrets: %w", closeErr)
	}
	return ParseBytes(data)
}

// ParseBytes parses deterministic named-secret records.
func ParseBytes(data []byte) (map[string]string, error) {
	if len(data) > maxBytes {
		return nil, fmt.Errorf("named secrets exceed %d bytes", maxBytes)
	}
	secrets := make(map[string]string)
	for lineNumber, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		name, secret, found := strings.Cut(trimmed, "=")
		name, secret = strings.TrimSpace(name), strings.TrimSpace(secret)
		if !found || !validName(name) || secret == "" {
			return nil, fmt.Errorf("line %d: expected `name = secret`", lineNumber+1)
		}
		if _, exists := secrets[name]; exists {
			return nil, fmt.Errorf("line %d: duplicate identity %q", lineNumber+1, name)
		}
		secrets[name] = secret
	}
	if len(secrets) == 0 {
		return nil, errors.New("named secrets contain no identities")
	}
	return secrets, nil
}

// Render returns sorted `name = secret` records.
func Render(secrets map[string]string) ([]byte, error) {
	if len(secrets) == 0 {
		return nil, errors.New("named secrets contain no identities")
	}
	names := make([]string, 0, len(secrets))
	for name, secret := range secrets {
		if !validName(name) || strings.TrimSpace(secret) == "" || strings.ContainsAny(secret, "\r\n") {
			return nil, fmt.Errorf("invalid named secret %q", name)
		}
		names = append(names, name)
	}
	slices.Sort(names)
	var output strings.Builder
	for _, name := range names {
		fmt.Fprintf(&output, "%s = %s\n", name, strings.TrimSpace(secrets[name]))
	}
	return []byte(output.String()), nil
}

func validName(name string) bool {
	return identityPattern.MatchString(name)
}
