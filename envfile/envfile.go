// Package envfile reads the strict environment files generated for broker services.
package envfile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
)

const maxEnvironmentFileBytes = 1024 * 1024

// Load reads a broker environment file without interpreting shell syntax.
func Load(path string) (map[string]string, error) {
	file, err := os.Open(path) // #nosec G304 -- path is an explicit operator input.
	if err != nil {
		return nil, fmt.Errorf("open broker environment file: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxEnvironmentFileBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, errors.New("read broker environment file")
	}
	if closeErr != nil {
		return nil, errors.New("close broker environment file")
	}
	if len(data) > maxEnvironmentFileBytes {
		return nil, fmt.Errorf("broker environment file exceeds %d bytes", maxEnvironmentFileBytes)
	}
	return Parse(data)
}

// Parse parses literal KEY=VALUE assignments. Blank lines and comments are allowed.
func Parse(data []byte) (map[string]string, error) {
	values := make(map[string]string)
	for index, raw := range strings.Split(string(data), "\n") {
		key, value, skip, err := parseLine(raw, index+1)
		if err != nil {
			return nil, err
		}
		if skip {
			continue
		}
		if _, exists := values[key]; exists {
			return nil, fmt.Errorf("broker environment file line %d repeats key %s", index+1, key)
		}
		values[key] = value
	}
	return values, nil
}

func parseLine(raw string, lineNumber int) (string, string, bool, error) {
	line := strings.TrimSuffix(raw, "\r")
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", true, nil
	}
	key, value, ok := strings.Cut(line, "=")
	if line != trimmed || !ok || !validKey(key) || invalidValue(value) {
		return "", "", false, fmt.Errorf("broker environment file line %d is invalid", lineNumber)
	}
	return key, value, false, nil
}

// OverlayLookup returns primary values first, then values loaded from a file.
func OverlayLookup(values map[string]string, primary func(string) string) func(string) string {
	return func(key string) string {
		if primary != nil {
			if value := primary(key); value != "" {
				return value
			}
		}
		return values[key]
	}
}

func validKey(value string) bool {
	if value == "" || !isKeyStart(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		if !isKeyCharacter(value[index]) {
			return false
		}
	}
	return true
}

func isKeyStart(value byte) bool {
	return value == '_' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func isKeyCharacter(value byte) bool {
	return isKeyStart(value) || value >= '0' && value <= '9'
}

func invalidValue(value string) bool {
	return value == "" || strings.ContainsAny(value, "\x00\r\n\\\"'") || strings.IndexFunc(value, unicode.IsSpace) >= 0
}
