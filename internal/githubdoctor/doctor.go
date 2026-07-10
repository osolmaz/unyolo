// Package githubdoctor verifies local isolation and GitHub-native enforcement.
package githubdoctor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	bkdoctor "github.com/osolmaz/brokerkit/doctor"
	"github.com/osolmaz/gh-broker/internal/config"
	"github.com/osolmaz/gh-broker/internal/githubapp"
)

const maxDoctorResponseBytes = 1 << 20

var lookupIdentity = bkdoctor.LookupIdentity

// Options configures one GitHub deployment inspection.
type Options struct {
	AgentUser         string
	ServiceUser       string
	Repo              string
	RequireProtection bool
	APIBaseURL        *url.URL
	HTTPClient        *http.Client
}

// Run executes secret-safe local and GitHub checks.
func Run(ctx context.Context, cfg config.Config, opts Options) (bkdoctor.Report, error) {
	agent, err := lookupIdentity(opts.AgentUser)
	if err != nil {
		return bkdoctor.Report{}, err
	}
	service, err := lookupIdentity(opts.ServiceUser)
	if err != nil {
		return bkdoctor.Report{}, err
	}
	owner, repo, err := parseRepo(opts.Repo)
	if err != nil {
		return bkdoctor.Report{}, err
	}
	checks := []bkdoctor.Check{bkdoctor.RootEquivalentCheck(agent), bkdoctor.SeparationCheck(agent, service)}
	checks = append(checks, localSecretChecks(cfg, agent)...)
	checks = append(checks, githubChecks(ctx, cfg, opts, owner, repo)...)
	return bkdoctor.NewReport(agent, checks...), nil
}

func localSecretChecks(cfg config.Config, agent bkdoctor.Identity) []bkdoctor.Check {
	paths := []string{cfg.GitHubTokenFile, cfg.GitHubAppPrivateKeyFile, cfg.GitHubWebhookSecretFile, cfg.SecretsFile}
	checks := make([]bkdoctor.Check, 0, len(paths)*5)
	for _, path := range paths {
		if path != "" {
			checks = append(checks, bkdoctor.SecretFileChecks(path, agent)...)
		}
	}
	checks = append(checks, inlineCredentialChecks(cfg)...)
	return checks
}

func inlineCredentialChecks(cfg config.Config) []bkdoctor.Check {
	checks := make([]bkdoctor.Check, 0, 4)
	checks = appendInlineCredentialCheck(checks, cfg.SharedSecret != "" && cfg.SecretsFile == "", "broker_client_secret")
	checks = appendInlineCredentialCheck(checks, cfg.GitHubToken != "" && cfg.GitHubTokenFile == "", "github_token")
	checks = appendInlineCredentialCheck(checks, cfg.GitHubWebhookSecret != "" && cfg.GitHubWebhookSecretFile == "", "github_webhook_secret")
	checks = appendInlineCredentialCheck(checks, cfg.TelegramBotToken != "", "telegram_bot_token")
	return checks
}

func appendInlineCredentialCheck(checks []bkdoctor.Check, configured bool, credential string) []bkdoctor.Check {
	if !configured {
		return checks
	}
	return append(checks, bkdoctor.Check{
		Status:  bkdoctor.CheckUnknown,
		Name:    "inline_" + credential + "_isolation",
		Message: "inline credential isolation cannot be verified; use a protected credential file",
	})
}

func githubChecks(ctx context.Context, cfg config.Config, opts Options, owner string, repo string) []bkdoctor.Check {
	baseURL := opts.APIBaseURL
	if baseURL == nil {
		baseURL, _ = url.Parse("https://api.github.com")
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	token, installationChecks := githubDoctorToken(ctx, cfg, baseURL, client, owner, repo)
	checks := append([]bkdoctor.Check(nil), installationChecks...)
	if token == "" {
		return checks
	}
	defaultBranch, err := fetchDefaultBranch(ctx, client, baseURL, token, owner, repo)
	checks = append(checks, resultCheck("github_repo_visible", "configured repository is visible", "configured repository is not visible", err))
	if err != nil {
		return checks
	}
	checks = append(checks, bkdoctor.Check{Status: bkdoctor.CheckPass, Name: "github_default_branch", Message: "default branch is " + defaultBranch})
	protected, protectionErr := branchProtected(ctx, client, baseURL, token, owner, repo, defaultBranch)
	checks = append(checks, protectionCheck(opts.RequireProtection, protected, protectionErr))
	return checks
}

func githubDoctorToken(ctx context.Context, cfg config.Config, baseURL *url.URL, client *http.Client, owner string, repo string) (string, []bkdoctor.Check) {
	if cfg.GitHubAppID != "" || len(cfg.GitHubAppPrivateKey) > 0 {
		source, err := githubapp.New(githubapp.Config{AppID: cfg.GitHubAppID, PrivateKeyPEM: cfg.GitHubAppPrivateKey, APIBaseURL: baseURL, HTTPClient: client})
		if err != nil {
			return "", []bkdoctor.Check{resultCheck("github_app_jwt", "GitHub App JWT can be signed", "GitHub App JWT cannot be signed", err)}
		}
		return githubAppDoctorToken(ctx, source, owner, repo)
	}
	if cfg.GitHubToken == "" {
		return "", []bkdoctor.Check{{Status: bkdoctor.CheckFail, Name: "github_credentials", Message: "no GitHub credential is configured"}}
	}
	return cfg.GitHubToken, []bkdoctor.Check{{Status: bkdoctor.CheckWarn, Name: "github_app_credentials", Message: "development token fallback cannot prove GitHub App permissions"}}
}

func githubAppDoctorToken(ctx context.Context, source *githubapp.Source, owner string, repo string) (string, []bkdoctor.Check) {
	_, jwtErr := source.JWT()
	checks := []bkdoctor.Check{resultCheck("github_app_jwt", "GitHub App JWT can be signed", "GitHub App JWT cannot be signed", jwtErr)}
	if jwtErr != nil {
		return "", checks
	}
	token, tokenErr := source.InstallationTokenForRepo(ctx, owner, repo)
	checks = append(checks, resultCheck("github_installation_token", "installation token can be minted for the configured repository", "installation token cannot be minted for the configured repository", tokenErr))
	if tokenErr != nil {
		return "", checks
	}
	checks = append(checks, permissionCheck(token.Permissions))
	return token.Value, checks
}

func permissionCheck(permissions map[string]string) bkdoctor.Check {
	allowed := map[string]map[string]bool{
		"checks":        {"read": true},
		"contents":      {"write": true},
		"metadata":      {"read": true},
		"pull_requests": {"write": true},
	}
	for permission, level := range permissions {
		if !allowed[permission][level] {
			return bkdoctor.Check{Status: bkdoctor.CheckFail, Name: "github_app_permissions", Message: "GitHub App installation token has an unexpected permission or access level"}
		}
	}
	if permissions["contents"] != "write" || permissions["pull_requests"] != "write" {
		return bkdoctor.Check{Status: bkdoctor.CheckFail, Name: "github_app_permissions", Message: "GitHub App lacks required contents and pull request permissions"}
	}
	return bkdoctor.Check{Status: bkdoctor.CheckPass, Name: "github_app_permissions", Message: "GitHub App has required repository permissions without known broad administration writes"}
}

func fetchDefaultBranch(ctx context.Context, client *http.Client, baseURL *url.URL, token string, owner string, repo string) (string, error) {
	var payload struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := githubJSON(ctx, client, baseURL.JoinPath("repos", owner, repo), token, &payload); err != nil {
		return "", err
	}
	payload.DefaultBranch = strings.TrimSpace(payload.DefaultBranch)
	if payload.DefaultBranch == "" {
		return "", errors.New("repository response omitted default branch")
	}
	return payload.DefaultBranch, nil
}

func branchProtected(ctx context.Context, client *http.Client, baseURL *url.URL, token string, owner string, repo string, branch string) (bool, error) {
	var rules []json.RawMessage
	err := githubJSON(ctx, client, baseURL.JoinPath("repos", owner, repo, "rules", "branches", branch), token, &rules)
	if err == nil && len(rules) > 0 {
		return true, nil
	}
	var protection map[string]any
	protectionErr := githubJSON(ctx, client, baseURL.JoinPath("repos", owner, repo, "branches", branch, "protection"), token, &protection)
	if protectionErr == nil {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, protectionErr
}

type githubStatusError struct {
	code int
}

func (err githubStatusError) Error() string {
	return fmt.Sprintf("GitHub API returned status %d", err.code)
}

func githubJSON(ctx context.Context, client *http.Client, endpoint *url.URL, token string, out any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, err := client.Do(request)
	if err != nil {
		return errors.New("GitHub API request failed")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return githubStatusError{code: response.StatusCode}
	}
	body, err := readDoctorResponse(response.Body)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return errors.New("GitHub API response was invalid")
	}
	return nil
}

func readDoctorResponse(body io.Reader) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(body, maxDoctorResponseBytes+1))
	if err != nil || len(payload) > maxDoctorResponseBytes {
		return nil, errors.New("GitHub API response was invalid")
	}
	return payload, nil
}

func protectionCheck(required bool, protected bool, err error) bkdoctor.Check {
	if protected {
		return bkdoctor.Check{Status: bkdoctor.CheckPass, Name: "github_default_branch_protected", Message: "default branch has an applicable ruleset or branch protection"}
	}
	if !required {
		return bkdoctor.Check{Status: bkdoctor.CheckWarn, Name: "github_default_branch_protected", Message: "default branch protection was not required by this doctor run"}
	}
	var statusErr githubStatusError
	if err != nil && (!errors.As(err, &statusErr) || statusErr.code != http.StatusNotFound) {
		return bkdoctor.Check{Status: bkdoctor.CheckUnknown, Name: "github_default_branch_protected", Message: "default branch protection could not be inspected with the configured credential"}
	}
	return bkdoctor.Check{Status: bkdoctor.CheckFail, Name: "github_default_branch_protected", Message: "default branch has no verifiable ruleset or branch protection"}
}

func resultCheck(name string, passMessage string, failMessage string, err error) bkdoctor.Check {
	if err != nil {
		return bkdoctor.Check{Status: bkdoctor.CheckFail, Name: name, Message: failMessage}
	}
	return bkdoctor.Check{Status: bkdoctor.CheckPass, Name: name, Message: passMessage}
}

func parseRepo(value string) (string, string, error) {
	owner, repo, ok := strings.Cut(strings.TrimSpace(value), "/")
	if !ok || owner == "" || repo == "" || strings.Contains(repo, "/") {
		return "", "", errors.New("repo must be owner/name")
	}
	return owner, repo, nil
}
