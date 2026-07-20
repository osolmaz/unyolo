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
	ModeAll Mode = "all"
)

// Options controls an install, status, doctor, or uninstall operation.
type Options struct {
	HomeDir            string
	Repository         string
	Mode               Mode
	Replace            bool
	Runner             Runner
	HTTP               *http.Client
	repositoryOptional bool
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
	Run(context.Context, ...string) ([]byte, error)
}

type commandRunner struct{ home string }

func (r commandRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	// #nosec G204 -- the executable is fixed and callers assemble structured Git config arguments.
	command := exec.CommandContext(ctx, "git", args...)
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
	if err := validateReplacement(current, origin, opts); err != nil {
		return Status{}, err
	}
	if current.Installed {
		if err := verifyInstallation(ctx, provider, current, runner); err != nil {
			return Status{}, fmt.Errorf("verify existing BrokerKit Git installation: %w", err)
		}
	}
	if err := rejectConflicts(ctx, provider, origin, opts.Mode, current, runner); err != nil {
		return Status{}, err
	}
	if !current.Installed {
		if err := verifyCredentialHelper(ctx, provider, runner); err != nil {
			return Status{}, err
		}
	}
	return replaceInstallation(ctx, provider, current, origin, opts.Mode, runner)
}

func validateReplacement(current Status, origin string, opts Options) error {
	if current.Installed && (current.Origin != origin || current.Mode != opts.Mode) && !opts.Replace {
		return errors.New("BrokerKit Git routing already exists with different settings; rerun with --replace")
	}
	return nil
}

func replaceInstallation(ctx context.Context, provider Provider, current Status, origin string, mode Mode, runner Runner) (Status, error) {
	if current.Installed {
		if err := remove(ctx, provider, current, runner); err != nil {
			return Status{}, err
		}
	}
	if err := writeConfig(ctx, provider, origin, mode, runner); err != nil {
		return Status{}, rollbackReplacement(ctx, provider, current, Status{
			Provider: provider.ID, Mode: mode, Origin: origin, Installed: true,
		}, runner, err)
	}
	return Status{Provider: provider.ID, Mode: mode, Origin: origin, Installed: true}, nil
}

func rollbackReplacement(
	ctx context.Context,
	provider Provider,
	previous Status,
	partial Status,
	runner Runner,
	installErr error,
) error {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	errs := []error{installErr}
	if err := remove(rollbackCtx, provider, partial, runner); err != nil {
		errs = append(errs, fmt.Errorf("clean up partial BrokerKit Git installation: %w", err))
	}
	if previous.Installed && previous.Origin == partial.Origin {
		if err := writeConfig(rollbackCtx, provider, previous.Origin, previous.Mode, runner); err != nil {
			errs = append(errs, fmt.Errorf("restore previous BrokerKit Git installation: %w", err))
		}
	}
	return errors.Join(errs...)
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
	if err := validateDoctorInstallation(ctx, provider, status, origin, runner); err != nil {
		return Status{}, err
	}
	if err := verifyRepository(ctx, provider, origin, opts, runner); err != nil {
		return Status{}, err
	}
	if err := checkIdentity(ctx, opts.HTTP, origin, client.SharedSecret, provider.ID); err != nil {
		return Status{}, err
	}
	return status, nil
}

func validateDoctorInstallation(ctx context.Context, provider Provider, status Status, origin string, runner Runner) error {
	if !status.Installed || status.Origin != origin {
		return errors.New("BrokerKit Git routing is not installed for the configured listener")
	}
	if err := rejectConflicts(ctx, provider, origin, status.Mode, status, runner); err != nil {
		return err
	}
	return verifyInstallation(ctx, provider, status, runner)
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
	if err := normalizeOptions(opts); err != nil {
		return nil, err
	}
	runner := opts.Runner
	if runner == nil {
		runner = commandRunner{home: opts.HomeDir}
	}
	return runner, nil
}

func normalizeOptions(opts *Options) error {
	home, err := configuredHome(opts.HomeDir)
	if err != nil {
		return err
	}
	opts.HomeDir = home
	if opts.Repository != "" && !normalizedAbsolutePath(opts.Repository) {
		return errors.New("repository path must be absolute and normalized")
	}
	opts.Mode = ModeAll
	return nil
}

func configuredHome(home string) (string, error) {
	if home == "" {
		resolved, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		home = resolved
	}
	if !filepath.IsAbs(home) {
		return "", errors.New("home directory must be absolute")
	}
	return home, nil
}

func normalizedAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func validateProvider(provider Provider) error {
	if provider.ID == "" || provider.BrokerName == "" || provider.EnvPrefix == "" || len(provider.CanonicalPrefixes) == 0 {
		return errors.New("complete Git provider descriptor is required")
	}
	for _, prefix := range provider.CanonicalPrefixes {
		if !validCanonicalPrefix(prefix) {
			return errors.New("provider contains an invalid canonical Git prefix")
		}
	}
	return nil
}

func validCanonicalPrefix(prefix string) bool {
	if strings.Contains(prefix, "@") && strings.Contains(prefix, ":") {
		return !strings.ContainsAny(prefix, "\r\n")
	}
	parsed, err := url.Parse(prefix)
	return err == nil && parsed.Scheme != "" && parsed.Host != ""
}

func gitOrigin(raw string) (string, error) {
	parsed, err := endpoint.Parse(raw, endpoint.ParseOptions{})
	if err != nil || parsed.Scheme() != endpoint.SchemeTCP || parsed.Exposure() != endpoint.ExposureLoopback {
		return "", errors.New("git listener must be a loopback tcp endpoint")
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
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("BrokerKit Git listener returned HTTP %d", response.StatusCode)
	}
	var identity struct {
		Provider string `json:"provider"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 4097))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&identity); err != nil || identity.Provider != provider {
		return errors.New("git listener identity does not match the requested provider")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("git listener identity response has trailing data")
	}
	return nil
}

func writeConfig(ctx context.Context, provider Provider, origin string, mode Mode, runner Runner) error {
	rewriteKey := "url." + origin + "/.insteadOf"
	for _, prefix := range provider.CanonicalPrefixes {
		if _, err := runner.Run(ctx, "config", "--global", "--add", rewriteKey, prefix); err != nil {
			return fmt.Errorf("write Git URL routing: %w", err)
		}
	}
	credentialKey := "credential." + origin
	commands := [][]string{
		{"config", "--global", "--replace-all", credentialKey + ".helper", ""},
		{"config", "--global", "--add", credentialKey + ".helper", "brokerkit --provider " + provider.ID},
		{"config", "--global", credentialKey + ".useHttpPath", "true"},
		{"config", "--global", "http." + origin + ".proxy", ""},
		{"config", "--global", statusKey(provider, "origin"), origin},
		{"config", "--global", statusKey(provider, "mode"), string(mode)},
	}
	for _, command := range commands {
		if _, err := runner.Run(ctx, command...); err != nil {
			return fmt.Errorf("write BrokerKit Git configuration: %w", err)
		}
	}
	return nil
}

func remove(ctx context.Context, provider Provider, status Status, runner Runner) error {
	key := "url." + status.Origin + "/.insteadOf"
	for _, prefix := range provider.CanonicalPrefixes {
		if _, err := runner.Run(ctx, "config", "--global", "--fixed-value", "--unset-all", key, prefix); err != nil && !isMissingConfig(err) {
			return fmt.Errorf("remove Git URL routing: %w", err)
		}
	}
	for _, section := range []string{"credential." + status.Origin, "brokerkit.git." + provider.ID} {
		if _, err := runner.Run(ctx, "config", "--global", "--remove-section", section); err != nil && !isMissingConfig(err) {
			return fmt.Errorf("remove BrokerKit Git configuration: %w", err)
		}
	}
	return removeProxyIsolation(ctx, status.Origin, runner)
}

func removeProxyIsolation(ctx context.Context, origin string, runner Runner) error {
	if _, err := runner.Run(ctx, "config", "--global", "--unset-all", "http."+origin+".proxy"); err != nil && !isMissingConfig(err) {
		return fmt.Errorf("remove Git proxy isolation: %w", err)
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
	if mode != ModeAll {
		return Status{}, errors.New("BrokerKit Git ownership metadata has an invalid mode")
	}
	return Status{Provider: provider.ID, Origin: origin, Mode: mode, Installed: true}, nil
}

func rejectConflicts(ctx context.Context, provider Provider, origin string, mode Mode, current Status, runner Runner) error {
	expectedKeys := map[string]bool{}
	if current.Installed {
		expectedKeys[strings.ToLower("url."+current.Origin+"/.insteadOf")] = true
	}
	if err := rejectRewriteScope(ctx, runner, "--system", provider.CanonicalPrefixes, nil); err != nil {
		return err
	}
	if err := rejectRewriteScope(ctx, runner, "--global", provider.CanonicalPrefixes, expectedKeys); err != nil {
		return err
	}
	for _, scope := range []string{"--system", "--global"} {
		if err := rejectInheritedTransportOverrides(ctx, runner, scope); err != nil {
			return err
		}
		if err := rejectScopedProxyOverrides(ctx, runner, origin, scope, ""); err != nil {
			return err
		}
	}
	if !current.Installed || current.Origin != origin {
		if err := rejectUnownedCredentialScope(ctx, origin, runner); err != nil {
			return err
		}
	}
	return nil
}

func rejectUnownedCredentialScope(ctx context.Context, origin string, runner Runner) error {
	key := "credential." + origin + ".helper"
	for _, scope := range []string{"--system", "--global"} {
		output, err := runner.Run(ctx, "config", scope, "--includes", "--get-all", key)
		if err != nil {
			if isMissingConfig(err) {
				continue
			}
			return fmt.Errorf("inspect Git credential helper configuration: %w", err)
		}
		if len(output) > 0 {
			return fmt.Errorf("git credential helper configuration %s already exists for the BrokerKit listener", key)
		}
	}
	return nil
}

func rejectRewriteScope(ctx context.Context, runner Runner, scope string, prefixes []string, expected map[string]bool, roots ...string) error {
	args := []string{"config", scope, "--includes", "--null", "--get-regexp", "^url\\..*\\.(insteadof|pushinsteadof)$"}
	if len(roots) > 0 {
		args = append([]string{"-C", roots[0]}, args...)
	}
	output, err := runner.Run(ctx, args...)
	if err != nil && !isMissingConfig(err) {
		return err
	}
	return rejectRewriteRecords(output, prefixes, expected)
}

func rejectRewriteRecords(output []byte, prefixes []string, expected map[string]bool) error {
	for _, record := range bytes.Split(output, []byte{0}) {
		key, value, conflict := conflictingRewrite(record, prefixes, expected)
		if conflict {
			return fmt.Errorf("git URL %q is already routed by %s", value, key)
		}
	}
	return nil
}

func verifyRepository(ctx context.Context, provider Provider, origin string, opts Options, runner Runner) error {
	if opts.Repository == "" {
		return nil
	}
	root, found, err := repositoryRoot(ctx, opts.Repository, opts.repositoryOptional, runner)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	return runRepositoryChecks(
		func() error { return verifyRepositoryInheritedConfig(ctx, provider, origin, root, runner) },
		func() error { return rejectRepositoryRewrites(ctx, provider, root, runner) },
		func() error { return rejectRepositoryTransportConfig(ctx, root, "--local", runner) },
		func() error { return rejectScopedProxyOverrides(ctx, runner, origin, "--local", root) },
		func() error { return verifyRepositoryWorktreeConfig(ctx, provider, origin, root, runner) },
		func() error { return rejectRepositoryLFSConfig(ctx, root, runner) },
	)
}

func verifyRepositoryInheritedConfig(ctx context.Context, provider Provider, origin, root string, runner Runner) error {
	expectedKeys := map[string]bool{strings.ToLower("url." + origin + "/.insteadOf"): true}
	if err := rejectRewriteScope(ctx, runner, "--system", provider.CanonicalPrefixes, nil, root); err != nil {
		return err
	}
	if err := rejectRewriteScope(ctx, runner, "--global", provider.CanonicalPrefixes, expectedKeys, root); err != nil {
		return err
	}
	for _, scope := range []string{"--system", "--global"} {
		if err := rejectInheritedTransportOverrides(ctx, runner, scope, root); err != nil {
			return err
		}
		if err := rejectScopedProxyOverrides(ctx, runner, origin, scope, root); err != nil {
			return err
		}
	}
	return nil
}

func verifyRepositoryWorktreeConfig(ctx context.Context, provider Provider, origin, root string, runner Runner) error {
	worktreeConfig, err := repositoryWorktreeConfigEnabled(ctx, root, runner)
	if err != nil || !worktreeConfig {
		return err
	}
	return runRepositoryChecks(
		func() error { return rejectRepositoryRewritesAtScope(ctx, provider, root, "--worktree", runner) },
		func() error { return rejectRepositoryTransportConfig(ctx, root, "--worktree", runner) },
		func() error { return rejectScopedProxyOverrides(ctx, runner, origin, "--worktree", root) },
	)
}

func runRepositoryChecks(checks ...func() error) error {
	for _, check := range checks {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

func rejectInheritedTransportOverrides(ctx context.Context, runner Runner, scope string, roots ...string) error {
	args := []string{"config", scope, "--includes", "--null", "--get-regexp", "^(lfs\\.(url|pushurl)|remote\\..*\\.(pushurl|lfsurl|lfspushurl))$"}
	if len(roots) > 0 {
		args = append([]string{"-C", roots[0]}, args...)
	}
	output, err := runner.Run(ctx, args...)
	if err != nil {
		if isMissingConfig(err) {
			return nil
		}
		return fmt.Errorf("inspect %s Git LFS configuration: %w", strings.TrimPrefix(scope, "--"), err)
	}
	key, _, _ := bytes.Cut(bytes.Split(output, []byte{0})[0], []byte{'\n'})
	return fmt.Errorf("%s Git transport override %s bypasses BrokerKit", strings.TrimPrefix(scope, "--"), key)
}

func rejectScopedProxyOverrides(ctx context.Context, runner Runner, origin, scope, root string) error {
	args := []string{"config", scope, "--includes", "--null", "--get-regexp", "^http\\..*\\.proxy$"}
	if root != "" {
		args = append([]string{"-C", root}, args...)
	}
	output, err := runner.Run(ctx, args...)
	if err != nil {
		if isMissingConfig(err) {
			return nil
		}
		return fmt.Errorf("inspect Git proxy configuration: %w", err)
	}
	return rejectScopedProxyRecords(output, origin, scope)
}

func rejectScopedProxyRecords(output []byte, origin, scope string) error {
	ownedKey := strings.ToLower("http." + origin + ".proxy")
	for _, record := range bytes.Split(output, []byte{0}) {
		key, value, ok := bytes.Cut(record, []byte{'\n'})
		if !ok || !proxyKeyMatchesOrigin(string(key), origin) {
			continue
		}
		if scope == "--global" && strings.ToLower(string(key)) == ownedKey && len(value) == 0 {
			continue
		}
		return fmt.Errorf("git proxy override %s could expose the BrokerKit client credential", key)
	}
	return nil
}

func proxyKeyMatchesOrigin(key, origin string) bool {
	lower := strings.ToLower(key)
	if !strings.HasPrefix(lower, "http.") || !strings.HasSuffix(lower, ".proxy") {
		return false
	}
	rawURL := key[len("http.") : len(key)-len(".proxy")]
	candidate, candidateErr := url.Parse(rawURL)
	listener, listenerErr := url.Parse(origin)
	return candidateErr == nil && listenerErr == nil &&
		strings.EqualFold(candidate.Scheme, listener.Scheme) && strings.EqualFold(candidate.Host, listener.Host)
}

func repositoryRoot(ctx context.Context, repository string, optional bool, runner Runner) (string, bool, error) {
	output, err := runner.Run(ctx, "-C", repository, "rev-parse", "--show-toplevel")
	if err != nil {
		if optional && strings.Contains(err.Error(), "not a git repository") {
			return "", false, nil
		}
		return "", false, fmt.Errorf("inspect repository: %w", err)
	}
	root := strings.TrimSpace(string(output))
	if !normalizedAbsolutePath(root) {
		return "", false, errors.New("git returned an invalid repository root")
	}
	return root, true, nil
}

func rejectRepositoryLFSConfig(ctx context.Context, root string, runner Runner) error {
	lfsConfig := filepath.Join(root, ".lfsconfig")
	_, err := os.Stat(lfsConfig)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect repository .lfsconfig: %w", err)
	}
	return rejectRepositoryTransportConfig(ctx, root, "--file", runner, lfsConfig)
}

func rejectRepositoryRewrites(ctx context.Context, provider Provider, root string, runner Runner) error {
	return rejectRepositoryRewritesAtScope(ctx, provider, root, "--local", runner)
}

func rejectRepositoryRewritesAtScope(ctx context.Context, provider Provider, root, scope string, runner Runner) error {
	output, err := runner.Run(ctx, "-C", root, "config", scope, "--includes", "--null", "--get-regexp", "^url\\..*\\.(insteadof|pushinsteadof)$")
	if err != nil && !isMissingConfig(err) {
		return fmt.Errorf("inspect repository URL routing: %w", err)
	}
	return rejectRewriteRecords(output, provider.CanonicalPrefixes, nil)
}

func repositoryWorktreeConfigEnabled(ctx context.Context, root string, runner Runner) (bool, error) {
	output, err := runner.Run(ctx, "-C", root, "config", "--local", "--bool", "extensions.worktreeConfig")
	if err != nil {
		if isMissingConfig(err) {
			return false, nil
		}
		return false, fmt.Errorf("inspect repository worktree configuration: %w", err)
	}
	return strings.TrimSpace(string(output)) == "true", nil
}

func rejectRepositoryTransportConfig(ctx context.Context, root, scope string, runner Runner, scopeArgs ...string) error {
	args := []string{"-C", root, "config", scope}
	args = append(args, scopeArgs...)
	args = append(args, "--includes", "--null", "--get-regexp", "^(lfs\\.(url|pushurl)|remote\\..*\\.(pushurl|lfsurl|lfspushurl))$")
	output, err := runner.Run(ctx, args...)
	if err != nil {
		if isMissingConfig(err) {
			return nil
		}
		return fmt.Errorf("inspect repository transport configuration: %w", err)
	}
	record := bytes.Split(output, []byte{0})[0]
	key, _, _ := bytes.Cut(record, []byte{'\n'})
	return fmt.Errorf("repository Git transport override %s bypasses BrokerKit", key)
}

func conflictingRewrite(record []byte, prefixes []string, expected map[string]bool) ([]byte, []byte, bool) {
	key, value, ok := bytes.Cut(record, []byte{'\n'})
	if !ok || !overlapsCanonicalPrefix(string(value), prefixes) {
		return nil, nil, false
	}
	return key, value, !expected[strings.ToLower(string(key))]
}

func overlapsCanonicalPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if value == prefix || strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func verifyInstallation(ctx context.Context, provider Provider, status Status, runner Runner) error {
	rewrites, err := configValues(ctx, runner, "url."+status.Origin+"/.insteadOf")
	if err != nil || !slices.Equal(rewrites, provider.CanonicalPrefixes) {
		return errors.New("BrokerKit Git URL routing is incomplete or modified")
	}
	helpers, err := configValues(ctx, runner, "credential."+status.Origin+".helper")
	wantHelpers := []string{"", "brokerkit --provider " + provider.ID}
	if err != nil || !slices.Equal(helpers, wantHelpers) {
		return errors.New("BrokerKit Git credential helper is incomplete or modified")
	}
	usePath, err := configValue(ctx, runner, "credential."+status.Origin+".useHttpPath")
	if err != nil || usePath != "true" {
		return errors.New("BrokerKit Git credential path isolation is incomplete or modified")
	}
	proxy, err := configValue(ctx, runner, "http."+status.Origin+".proxy")
	if err := verifyProxyIsolation(proxy, err); err != nil {
		return err
	}
	return verifyCredentialHelper(ctx, provider, runner)
}

func verifyCredentialHelper(ctx context.Context, provider Provider, runner Runner) error {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := runner.Run(checkCtx, "credential-brokerkit", "--provider", provider.ID, "capability"); err != nil {
		return fmt.Errorf("BrokerKit Git credential helper is unavailable: %w", err)
	}
	return nil
}

func verifyProxyIsolation(value string, err error) error {
	if err == nil && value == "" {
		return nil
	}
	return errors.New("BrokerKit Git proxy isolation is incomplete or modified")
}

func configValues(ctx context.Context, runner Runner, key string) ([]string, error) {
	output, err := runner.Run(ctx, "config", "--global", "--get-all", key)
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSuffix(string(output), "\n"), "\n"), nil
}

func configValue(ctx context.Context, runner Runner, key string) (string, error) {
	output, err := runner.Run(ctx, "config", "--global", "--get", key)
	return strings.TrimSpace(string(output)), err
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
