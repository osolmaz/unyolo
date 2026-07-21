package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/osolmaz/brokerkit/approval/notifier/telegram"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/operator/client"
)

const maxConfigBytes = 64 * 1024

type ingressConfig struct {
	TelegramBotTokenFile string                 `json:"telegram_bot_token_file"`
	TelegramChatID       int64                  `json:"telegram_chat_id"`
	InboxPath            string                 `json:"inbox_path"`
	InboxKeyFile         string                 `json:"inbox_key_file"`
	Routes               map[string]routeConfig `json:"routes"`
}

type routeConfig struct {
	OperatorEndpoint  string `json:"operator_endpoint"`
	OperatorTokenFile string `json:"operator_token_file"`
}

func loadIngressConfig(path string) (ingressConfig, error) {
	if !filepath.IsAbs(path) {
		return ingressConfig{}, errors.New("config path must be absolute")
	}
	data, err := readBoundedFile(path, maxConfigBytes)
	if err != nil {
		return ingressConfig{}, fmt.Errorf("read ingress config: %w", err)
	}
	var cfg ingressConfig
	if err := strictjson.Decode(data, &cfg, true); err != nil {
		return ingressConfig{}, fmt.Errorf("decode ingress config: %w", err)
	}
	if err := validateIngressConfig(cfg); err != nil {
		return ingressConfig{}, err
	}
	return cfg, nil
}

func validateIngressConfig(cfg ingressConfig) error {
	if !filepath.IsAbs(cfg.TelegramBotTokenFile) {
		return errors.New("telegram_bot_token_file must be absolute")
	}
	if cfg.TelegramChatID == 0 {
		return errors.New("telegram_chat_id is required")
	}
	if !filepath.IsAbs(cfg.InboxPath) || !filepath.IsAbs(cfg.InboxKeyFile) {
		return errors.New("inbox_path and inbox_key_file must be absolute")
	}
	if len(cfg.Routes) == 0 {
		return errors.New("at least one Telegram route is required")
	}
	for route, source := range cfg.Routes {
		if !supportedRoute(route) {
			return fmt.Errorf("unsupported Telegram route %q", route)
		}
		if strings.TrimSpace(source.OperatorEndpoint) == "" {
			return fmt.Errorf("route %q operator_endpoint is required", route)
		}
		if !filepath.IsAbs(source.OperatorTokenFile) {
			return fmt.Errorf("route %q operator_token_file must be absolute", route)
		}
	}
	return nil
}

func supportedRoute(route string) bool {
	switch route {
	case telegram.RouteHuggingFace, telegram.RouteGitHub, telegram.RouteSudo:
		return true
	default:
		return false
	}
}

//nolint:cyclop // Construction keeps every secret and route dependency failure attributable to its source.
func buildIngress(ctx context.Context, cfg ingressConfig) (*telegram.Client, *telegram.Dispatcher, *telegram.Inbox, error) {
	botToken, err := readSecretFile(cfg.TelegramBotTokenFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read Telegram bot token: %w", err)
	}
	client, err := telegram.New(botToken, cfg.TelegramChatID, nil, "")
	if err != nil {
		return nil, nil, nil, err
	}
	routes := make(map[string]telegram.OperatorSource, len(cfg.Routes))
	for route, source := range cfg.Routes {
		token, readErr := readSecretFile(source.OperatorTokenFile)
		if readErr != nil {
			return nil, nil, nil, fmt.Errorf("read route %q operator token: %w", route, readErr)
		}
		operator, clientErr := operatorclient.New(source.OperatorEndpoint, token, nil)
		if clientErr != nil {
			return nil, nil, nil, fmt.Errorf("configure route %q: %w", route, clientErr)
		}
		routes[route] = operator
	}
	dispatcher, err := telegram.NewDispatcher(routes)
	if err != nil {
		return nil, nil, nil, err
	}
	keyText, err := readSecretFile(cfg.InboxKeyFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read Telegram inbox key: %w", err)
	}
	key, err := hex.DecodeString(keyText)
	if err != nil || len(key) != 32 {
		return nil, nil, nil, errors.New("telegram inbox key is invalid")
	}
	inbox, err := telegram.OpenInbox(ctx, cfg.InboxPath, key)
	clearSecret(key)
	if err != nil {
		return nil, nil, nil, err
	}
	return client, dispatcher, inbox, nil
}

func clearSecret(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func readSecretFile(path string) (string, error) {
	data, err := readBoundedFile(path, 4096)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(data))
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("secret must be one nonempty line")
	}
	return value, nil
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- path is explicit trusted configuration.
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return data, nil
}
