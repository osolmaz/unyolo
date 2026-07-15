package admission

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/osolmaz/brokerkit/internal/strictjson"
)

const maxConfigBytes = 64 * 1024

type fileConfig struct {
	RequestsPerWindow int                        `json:"requests_per_window"`
	WindowSeconds     int64                      `json:"window_seconds"`
	ClientActive      int64                      `json:"client_active"`
	ClientPending     int64                      `json:"client_pending"`
	GlobalActive      int64                      `json:"global_active"`
	GlobalExecuting   int64                      `json:"global_executing"`
	Clients           map[string]fileClientLimit `json:"clients"`
}

type fileClientLimit struct {
	RequestsPerWindow int   `json:"requests_per_window"`
	WindowSeconds     int64 `json:"window_seconds"`
	Active            int64 `json:"active"`
	Pending           int64 `json:"pending"`
}

// LoadFile loads one closed, bounded admission configuration. An empty path
// selects conservative defaults.
func LoadFile(path string, clients []string) (Config, error) {
	if path == "" {
		return DefaultConfig(), nil
	}
	if !validConfigPath(path) {
		return Config{}, errors.New("admission config path must be absolute and normalized")
	}
	data, err := readConfigFile(path)
	if err != nil {
		return Config{}, err
	}
	return ParseConfig(data, clients)
}

func validConfigPath(path string) bool { return filepath.IsAbs(path) && filepath.Clean(path) == path }

func readConfigFile(path string) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- explicit operator-owned configuration path.
	if err != nil {
		return nil, errors.New("open admission config")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > maxConfigBytes {
		return nil, errors.New("read bounded admission config")
	}
	return data, nil
}

// ParseConfig parses one complete admission configuration for fixed clients.
func ParseConfig(data []byte, clients []string) (Config, error) {
	var wire fileConfig
	if err := strictjson.Decode(data, &wire, true); err != nil {
		return Config{}, fmt.Errorf("parse admission config: %w", err)
	}
	config := Config{Default: Limits{RequestsPerWindow: wire.RequestsPerWindow,
		Window: time.Duration(wire.WindowSeconds) * time.Second, ClientActive: wire.ClientActive,
		ClientPending: wire.ClientPending, GlobalActive: wire.GlobalActive, GlobalExecuting: wire.GlobalExecuting},
		Clients: make(map[string]ClientLimits, len(wire.Clients))}
	for client, limits := range wire.Clients {
		config.Clients[client] = ClientLimits{RequestsPerWindow: limits.RequestsPerWindow,
			Window: time.Duration(limits.WindowSeconds) * time.Second, Active: limits.Active, Pending: limits.Pending}
	}
	if _, err := NewConfigured(clients, config, func(context.Context, string) (Usage, error) { return Usage{}, nil }); err != nil {
		return Config{}, err
	}
	return config, nil
}
