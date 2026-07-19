// Package gitclient installs and diagnoses BrokerKit's user-level Git routing.
package gitclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/clientconfig"
	"github.com/osolmaz/brokerkit/endpoint"
)

const identityPath = "/_brokerkit/git/v1"

// Provider describes one broker-owned Git provider without embedding provider
// behavior in this package.
type Provider struct {
	ID                string
	BrokerName        string
	EnvPrefix         string
	CanonicalPrefixes []string
}

// Mode controls whether reads and writes or only writes are routed.
type Mode string

const (
	ModeAll      Mode = "all"
	ModePushOnly Mode = "push-only"
)

// Options controls an install, status, doctor, or uninstall operation.
type Options struct {
	HomeDir string
	Mode    Mode
	Replace bool
	Runner  Runner
	HTTP    *http.Client
}

// Status is the installed state for one provider.
type Status struct {
	Provider  string `json:"provider"`
	Mode      Mode   `json:"mode,omitempty"`
	Origin    string `json:"origin,omitempty"`
	Installed bool   `json:"installed"`
}

// Runner executes Git configuration commands.
type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type commandRunner struct{ home string }

func (r commandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = append(os.Environ(), "HOME="+r.home)
	command.Dir = r.home
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return nil, errors.New(message)
	}
	return output, nil
}

// Install configures one user's standard Git client to route through a broker.
func Install(ctx context.Context, provider Provider, opts Options) (Status, error) {
	client, origin, runner, err := prepare(provider, &opts)
	if err != nil {
		return Status{}, err
	}
	if err := checkIdentity(ctx, opts.HTTP, origin, client.SharedSecret, provider.ID); err != nil {
		return Status{}, err
	}
	current, err := readStatus(ctx, provider, runner)
	if err != nil {
		return Status{}, err
	}
	if current.Installed && (current.Origin != origin || current.Mode != opts.Mode) {
		if !opts.Replace {
			return Status{}, errors.New("BrokerKit Git routing already exists with different settings; rerun with --replace")
		}
	}
	if err := rejectConflicts(ctx, provider, origin, opts.Mode, runner); err != nil {
		return Status{}, err
	}
	if current.Installed {
		if err := remove(ctx, provider, current, runner); err != nil {
			return Status{}, err
		}
	}
	if err := writeConfig(ctx, provider, origin, opts.Mode, runner); err != nil {
		_ = remove(ctx, provider, Status{Provider: provider.ID, Mode: opts.Mode, Origin: origin, Installed: true}, runner)
		return Status{}, err
	}
	return Status{Provider: provider.ID, Mode: opts.Mode, Origin: origin, Installed: true}, nil
}

// Uninstall removes only configuration recorded as owned by BrokerKit.
func Uninstall(ctx context.Context, provider Provider, opts Options) (Status, error) {
	runner, err := prepareHome(provider, &opts)
	if err != nil {
		return Status{}, err
	}
	status, err := readStatus(ctx, provider, runner)
	if err != nil || !status.Installed {
		return status, err
	}
	if err := remove(ctx, provider, status, runner); err != nil {
		return Status{}, err
	}
	return Status{Provider: provider.ID}, nil
}

// Inspect reports the exact BrokerKit-owned installation state.
func Inspect(ctx context.Context, provider Provider, opts Options) (Status, error) {
	runner, err := prepareHome(provider, &opts)
	if err != nil {
		return Status{}, err
	}
	return readStatus(ctx, provider, runner)
}

// Doctor validates the installed state and authenticated listener identity.
func Doctor(ctx context.Context, provider Provider, opts Options) (Status, error) {
	client, origin, runner, err := prepare(provider, &opts)
	if err != nil {
		return Status{}, err
	}
	status, err := readStatus(ctx, provider, runner)
	if err != nil {
		return Status{}, err
	}
	if !status.Installed || status.Origin != origin {
		return Status{}, errors.New("BrokerKit Git routing is not installed for the configured listener")
	}
	if err := rejectConflicts(ctx, provider, origin, status.Mode, runner); err != nil {
		return Status{}, err
	}
	if err := checkIdentity(ctx, opts.HTTP, origin, client.SharedSecret, provider.ID); err != nil {
		return Status{}, err
	}
	return status, nil
}

func prepare(provider Provider, opts *Options) (clientconfig.Client, string, Runner, error) {
	runner, err := prepareHome(provider, opts)
	if err != nil {
		return clientconfig.Client{}, "", nil, err
	}
	client, err := clientconfig.Read(opts.HomeDir, provider.BrokerName, provider.EnvPrefix)
	if err != nil {
		return clientconfig.Client{}, "", nil, err
	}
	if client.GitEndpoint == "" {
		return clientconfig.Client{}, "", nil, errors.New("broker client configuration has no Git listener; rerun setup client with --git-endpoint")
	}
	origin, err := gitOrigin(client.GitEndpoint)
	return client, origin, runner, err
}

func prepareHome(provider Provider, opts *Options) (Runner, error) {
	if err := validateProvider(provider); err != nil {
		return nil, err
	}
	if opts.HomeDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolve home directory: %w", err)
		}
		opts.HomeDir = home
	}
	if !filepath.IsAbs(opts.HomeDir) {
		return nil, errors.New("home directory must be absolute")
	}
	if opts.Mode == "" {
		opts.Mode = ModeAll
	}
	if opts.Mode != ModeAll && opts.Mode != ModePushOnly {
		return nil, errors.New("mode must be all or push-only")
	}
	runner := opts.Runner
	if runner == nil {
		runner = commandRunner{home: opts.HomeDir}
	}
	return runner, nil
}

func validateProvider(provider Provider) error {
	if provider.ID == "" || provider.BrokerName == "" || provider.EnvPrefix == "" || len(provider.CanonicalPrefixes) == 0 {
		return errors.New("complete Git provider descriptor is required")
	}
	for _, prefix := range provider.CanonicalPrefixes {
		if strings.Contains(prefix, "@") && strings.Contains(prefix, ":") && !strings.ContainsAny(prefix, "\r\n") {
			continue
		}
		parsed, err := url.Parse(prefix)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return errors.New("provider contains an invalid canonical Git prefix")
		}
	}
	return nil
}

func gitOrigin(raw string) (string, error) {
	parsed, err := endpoint.Parse(raw, endpoint.ParseOptions{})
	if err != nil || parsed.Scheme() != endpoint.SchemeTCP || parsed.Exposure() != endpoint.ExposureLoopback {
		return "", errors.New("Git listener must be a loopback tcp endpoint")
	}
	return "http://" + parsed.Address(), nil
}

func checkIdentity(ctx context.Context, client *http.Client, origin, secret, provider string) error {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+identityPath, http.NoBody)
	if err != nil {
		return err
	}
	request.SetBasicAuth("brokerkit", secret)
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("reach BrokerKit Git listener: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("BrokerKit Git listener returned HTTP %d", response.StatusCode)
	}
	var identity struct {
		Provider string `json:"provider"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 4097))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&identity); err != nil || identity.Provider != provider {
		return errors.New("Git listener identity does not match the requested provider")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("Git listener identity response has trailing data")
	}
	return nil
}

func writeConfig(ctx context.Context, provider Provider, origin string, mode Mode, runner Runner) error {
	rewriteKey := "url." + origin + "/." + rewriteField(mode)
	for _, prefix := range provider.CanonicalPrefixes {
		if _, err := runner.Run(ctx, "git", "config", "--global", "--add", rewriteKey, prefix); err != nil {
			return fmt.Errorf("write Git URL routing: %w", err)
		}
	}
	credentialKey := "credential." + origin
	commands := [][]string{
		{"config", "--global", "--replace-all", credentialKey + ".helper", ""},
		{"config", "--global", "--add", credentialKey + ".helper", "brokerkit --provider " + provider.ID},
		{"config", "--global", credentialKey + ".useHttpPath", "true"},
		{"config", "--global", statusKey(provider, "origin"), origin},
		{"config", "--global", statusKey(provider, "mode"), string(mode)},
	}
	for _, command := range commands {
		if _, err := runner.Run(ctx, "git", command...); err != nil {
			return fmt.Errorf("write BrokerKit Git configuration: %w", err)
		}
	}
	return nil
}

func remove(ctx context.Context, provider Provider, status Status, runner Runner) error {
	key := "url." + status.Origin + "/." + rewriteField(status.Mode)
	for _, prefix := range provider.CanonicalPrefixes {
		if _, err := runner.Run(ctx, "git", "config", "--global", "--fixed-value", "--unset-all", key, prefix); err != nil && !isMissingConfig(err) {
			return fmt.Errorf("remove Git URL routing: %w", err)
		}
	}
	for _, section := range []string{"credential." + status.Origin, "brokerkit.git." + provider.ID} {
		if _, err := runner.Run(ctx, "git", "config", "--global", "--remove-section", section); err != nil && !isMissingConfig(err) {
			return fmt.Errorf("remove BrokerKit Git configuration: %w", err)
		}
	}
	return nil
}

func readStatus(ctx context.Context, provider Provider, runner Runner) (Status, error) {
	origin, originErr := configValue(ctx, runner, statusKey(provider, "origin"))
	modeValue, modeErr := configValue(ctx, runner, statusKey(provider, "mode"))
	if isMissingConfig(originErr) && isMissingConfig(modeErr) {
		return Status{Provider: provider.ID}, nil
	}
	if originErr != nil || modeErr != nil {
		return Status{}, errors.New("BrokerKit Git ownership metadata is incomplete")
	}
	mode := Mode(modeValue)
	if mode != ModeAll && mode != ModePushOnly {
		return Status{}, errors.New("BrokerKit Git ownership metadata has an invalid mode")
	}
	return Status{Provider: provider.ID, Origin: origin, Mode: mode, Installed: true}, nil
}

func rejectConflicts(ctx context.Context, provider Provider, origin string, mode Mode, runner Runner) error {
	output, err := runner.Run(ctx, "git", "config", "--global", "--null", "--get-regexp", "^url\\..*\\.(insteadof|pushinsteadof)$")
	if err != nil && !isMissingConfig(err) {
		return err
	}
	expectedKey := strings.ToLower("url." + origin + "/." + rewriteField(mode))
	for _, record := range bytes.Split(output, []byte{0}) {
		key, value, ok := bytes.Cut(record, []byte{'\n'})
		if !ok || !slices.Contains(provider.CanonicalPrefixes, string(value)) {
			continue
		}
		if strings.ToLower(string(key)) != expectedKey {
			return fmt.Errorf("Git URL %q is already routed by %s", value, key)
		}
	}
	return nil
}

func configValue(ctx context.Context, runner Runner, key string) (string, error) {
	output, err := runner.Run(ctx, "git", "config", "--global", "--get", key)
	return strings.TrimSpace(string(output)), err
}

func rewriteField(mode Mode) string {
	if mode == ModePushOnly {
		return "pushInsteadOf"
	}
	return "insteadOf"
}

func statusKey(provider Provider, field string) string {
	return "brokerkit.git." + provider.ID + "." + field
}

func isMissingConfig(err error) bool {
	if err == nil {
		return false
	}
	return strings.TrimSpace(err.Error()) == "exit status 1"
}
