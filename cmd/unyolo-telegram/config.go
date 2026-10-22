package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/osolmaz/unyolo/approval/notifier/telegram"
	clientconfig "github.com/osolmaz/unyolo/internal/config/client"
	"github.com/osolmaz/unyolo/internal/strictjson"
	"github.com/osolmaz/unyolo/operator/client"
)

const maxConfigBytes = 64 * 1024

type ingressConfig struct {
	TelegramBotTokenFile string                 `json:"telegram_bot_token_file"`
	TelegramAPIBase      string                 `json:"telegram_api_base,omitempty"`
	TelegramChatID       int64                  `json:"telegram_chat_id"`
	InboxPath            string                 `json:"inbox_path"`
	InboxKeyFile         string                 `json:"inbox_key_file"`
	Routes               map[string]routeConfig `json:"routes"`
}

// routeConfig points to the operator client document of one broker route. The
// document holds the broker's Operator V1 endpoint and this owner's operator
// credential, and belongs to the account that runs the owner.
type routeConfig struct {
	OperatorClientFile string `json:"operator_client_file"`
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
	if err := validateTelegramAPIBase(cfg.TelegramAPIBase); err != nil {
		return err
	}
	if cfg.TelegramChatID == 0 {
		return errors.New("telegram_chat_id is required")
	}
	if !filepath.IsAbs(cfg.InboxPath) || !filepath.IsAbs(cfg.InboxKeyFile) {
		return errors.New("inbox_path and inbox_key_file must be absolute")
	}
	return validateIngressRoutes(cfg.Routes)
}

func validateIngressRoutes(routes map[string]routeConfig) error {
	if len(routes) == 0 {
		return errors.New("at least one Telegram route is required")
	}
	for route, source := range routes {
		if !supportedRoute(route) {
			return fmt.Errorf("unsupported Telegram route %q", route)
		}
		if !filepath.IsAbs(source.OperatorClientFile) || filepath.Clean(source.OperatorClientFile) != source.OperatorClientFile {
			return fmt.Errorf("route %q operator_client_file must be absolute and clean", route)
		}
	}
	return nil
}

func validateTelegramAPIBase(value string) error {
	if value == "" {
		return nil
	}
	parsed, err := parseTelegramAPIBase(value)
	if err != nil {
		return err
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme != "http" || !loopbackHost(parsed.Hostname()) {
		return errors.New("telegram_api_base may use HTTP only for loopback")
	}
	return nil
}

func parseTelegramAPIBase(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || strings.Contains(value, "#") {
		return nil, errors.New("telegram_api_base must be an absolute HTTP URL without credentials, query, or fragment")
	}
	return parsed, nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func supportedRoute(route string) bool {
	switch route {
	case telegram.RouteHuggingFace, telegram.RouteGitHub, telegram.RouteSudo:
		return true
	default:
		return false
	}
}

// ingress is the single Telegram owner: it sends approval cards for every
// broker route and handles the clicks on them.
type ingress struct {
	client     *telegram.Client
	dispatcher *telegram.Dispatcher
	owner      *telegram.Owner
	inbox      *telegram.Inbox
}

func buildIngress(ctx context.Context, cfg ingressConfig) (ingress, error) {
	client, err := newTelegramClient(cfg)
	if err != nil {
		return ingress{}, err
	}
	sources, err := routeSources(cfg)
	if err != nil {
		return ingress{}, err
	}
	inbox, err := openIngressInbox(ctx, cfg)
	if err != nil {
		return ingress{}, err
	}
	built, err := assembleIngress(client, inbox, sources)
	if err != nil {
		_ = inbox.Close()
		return ingress{}, err
	}
	return built, nil
}

func newTelegramClient(cfg ingressConfig) (*telegram.Client, error) {
	botToken, err := readSecretFile(cfg.TelegramBotTokenFile)
	if err != nil {
		return nil, fmt.Errorf("read Telegram bot token: %w", err)
	}
	return telegram.New(botToken, cfg.TelegramChatID, nil, cfg.TelegramAPIBase)
}

func routeSources(cfg ingressConfig) (map[string]*operatorclient.Client, error) {
	sources := make(map[string]*operatorclient.Client, len(cfg.Routes))
	for route, source := range cfg.Routes {
		document, err := clientconfig.ReadOperatorPath(source.OperatorClientFile, os.Geteuid())
		if err != nil {
			return nil, fmt.Errorf("read route %q operator client: %w", route, err)
		}
		operator, err := operatorclient.New(document.Endpoint, document.Secret, nil)
		if err != nil {
			return nil, fmt.Errorf("configure route %q: %w", route, err)
		}
		sources[route] = operator
	}
	return sources, nil
}

func openIngressInbox(ctx context.Context, cfg ingressConfig) (*telegram.Inbox, error) {
	keyText, err := readSecretFile(cfg.InboxKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read Telegram inbox key: %w", err)
	}
	key, err := hex.DecodeString(keyText)
	if err != nil || len(key) != 32 {
		return nil, errors.New("telegram inbox key is invalid")
	}
	defer clearSecret(key)
	return telegram.OpenInbox(ctx, cfg.InboxPath, key)
}

func assembleIngress(client *telegram.Client, inbox *telegram.Inbox, sources map[string]*operatorclient.Client) (ingress, error) {
	operators := make(map[string]telegram.OperatorSource, len(sources))
	cards := make(map[string]telegram.CardSource, len(sources))
	for route, source := range sources {
		operators[route] = source
		cards[route] = source
	}
	dispatcher, err := telegram.NewDispatcher(operators, inbox)
	if err != nil {
		return ingress{}, err
	}
	owner, err := telegram.NewOwner(client, inbox, cards)
	if err != nil {
		return ingress{}, err
	}
	return ingress{client: client, dispatcher: dispatcher, owner: owner, inbox: inbox}, nil
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
