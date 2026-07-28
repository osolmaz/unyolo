// Package githubdoctor verifies local isolation and GitHub-native enforcement.
package githubdoctor

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/osolmaz/unyolo/brokers/github/internal/config"
	"github.com/osolmaz/unyolo/brokers/github/internal/githubauth"
	unyolodoctor "github.com/osolmaz/unyolo/internal/host/doctor"
)

var lookupIdentity = unyolodoctor.LookupIdentity

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
func Run(ctx context.Context, cfg config.Config, opts Options) (unyolodoctor.Report, error) {
	agent, err := lookupIdentity(opts.AgentUser)
	if err != nil {
		return unyolodoctor.Report{}, err
	}
	service, err := lookupIdentity(opts.ServiceUser)
	if err != nil {
		return unyolodoctor.Report{}, err
	}
	owner, repo, err := parseRepo(opts.Repo)
	if err != nil {
		return unyolodoctor.Report{}, err
	}
	checks := []unyolodoctor.Check{unyolodoctor.RootEquivalentCheck(agent), unyolodoctor.SeparationCheck(agent, service)}
	checks = append(checks, localSecretChecks(cfg, agent)...)
	storedCredentials, storedCheck := storedCredentialStatuses(cfg.StateDir, time.Now().UTC())
	if storedCheck != nil {
		checks = append(checks, *storedCheck)
	}
	checks = append(checks, githubChecks(ctx, cfg, opts, owner, repo)...)
	report := unyolodoctor.NewReport(agent, checks...)
	credentials := append(localCredentialStatuses(cfg, time.Now().UTC()), storedCredentials...)
	return unyolodoctor.WithCredentials(report, credentials...), nil
}

func localSecretChecks(cfg config.Config, agent unyolodoctor.Identity) []unyolodoctor.Check {
	paths := []string{cfg.GitHubTokenFile, cfg.GitHubAppPrivateKeyFile, cfg.GitHubAppClientSecretFile, cfg.GitHubWebhookSecretFile,
		cfg.SecretsFile, cfg.OperatorSecretsFile, cfg.TelegramBotTokenFile}
	checks := make([]unyolodoctor.Check, 0, len(paths)*5)
	for _, path := range paths {
		if path != "" {
			checks = append(checks, unyolodoctor.SecretFileChecks(path, agent)...)
		}
	}
	checks = append(checks, inlineCredentialChecks(cfg)...)
	return checks
}

func localCredentialStatuses(cfg config.Config, now time.Time) []unyolodoctor.CredentialStatus {
	const rotateAfter = unyolodoctor.DefaultCredentialRotationAge
	values := make([]unyolodoctor.CredentialStatus, 0, 7)
	values = appendCredentialFileStatus(values, "broker-client", cfg.SecretsFile, now, rotateAfter, unyolodoctor.CredentialRevocationLocal)
	values = appendCredentialFileStatus(values, "broker-operator", cfg.OperatorSecretsFile, now, rotateAfter, unyolodoctor.CredentialRevocationLocal)
	values = appendCredentialFileStatus(values, "github-development", cfg.GitHubTokenFile, now, rotateAfter, unyolodoctor.CredentialRevocationManual)
	values = appendCredentialFileStatus(values, "github-app-private-key", cfg.GitHubAppPrivateKeyFile, now, rotateAfter, unyolodoctor.CredentialRevocationManual)
	values = appendCredentialFileStatus(values, "github-app-client-secret", cfg.GitHubAppClientSecretFile, now, rotateAfter, unyolodoctor.CredentialRevocationManual)
	values = appendCredentialFileStatus(values, "github-webhook", cfg.GitHubWebhookSecretFile, now, rotateAfter, unyolodoctor.CredentialRevocationManual)
	values = appendCredentialFileStatus(values, "telegram-bot", cfg.TelegramBotTokenFile, now, rotateAfter, unyolodoctor.CredentialRevocationManual)
	return appendInlineCredentialStatuses(values, cfg)
}

func appendCredentialFileStatus(values []unyolodoctor.CredentialStatus, class, path string, now time.Time, rotateAfter time.Duration, revocation string) []unyolodoctor.CredentialStatus {
	if strings.TrimSpace(path) == "" {
		return values
	}
	return append(values, unyolodoctor.CredentialFileStatus(class, path, now, rotateAfter, time.Time{}, revocation))
}

func appendInlineCredentialStatuses(values []unyolodoctor.CredentialStatus, cfg config.Config) []unyolodoctor.CredentialStatus {
	inline := []struct {
		class, value, file, revocation string
	}{
		{"broker-client", cfg.SharedSecret, cfg.SecretsFile, unyolodoctor.CredentialRevocationLocal},
		{"broker-operator", cfg.OperatorSecret, cfg.OperatorSecretsFile, unyolodoctor.CredentialRevocationLocal},
		{"github-development", cfg.GitHubToken, cfg.GitHubTokenFile, unyolodoctor.CredentialRevocationManual},
		{"github-app-client-secret", cfg.GitHubAppClientSecret, cfg.GitHubAppClientSecretFile, unyolodoctor.CredentialRevocationManual},
		{"github-webhook", cfg.GitHubWebhookSecret, cfg.GitHubWebhookSecretFile, unyolodoctor.CredentialRevocationManual},
		{"telegram-bot", cfg.TelegramBotToken, cfg.TelegramBotTokenFile, unyolodoctor.CredentialRevocationManual},
	}
	for _, item := range inline {
		if item.value != "" && item.file == "" {
			values = append(values, unyolodoctor.InlineCredentialStatus(item.class, item.revocation))
		}
	}
	return values
}

func storedCredentialStatuses(stateDir string, now time.Time) ([]unyolodoctor.CredentialStatus, *unyolodoctor.Check) {
	if strings.TrimSpace(stateDir) == "" {
		return nil, nil
	}
	path, err := githubauth.UserCredentialStorePath(stateDir)
	if err != nil {
		return nil, storedCredentialCheck(unyolodoctor.CheckUnknown)
	}
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, storedCredentialCheck(unyolodoctor.CheckUnknown)
	}
	items, err := githubauth.InspectStoredUserCredentials(stateDir)
	if err != nil {
		return nil, storedCredentialCheck(unyolodoctor.CheckUnknown)
	}
	values := make([]unyolodoctor.CredentialStatus, 0, 2*len(items))
	for _, item := range items {
		id := strconv.FormatInt(item.UserID, 10)
		values = append(values,
			unyolodoctor.StoredCredentialStatus("github-user-access:"+id, item.UpdatedAt, item.AccessExpiresAt, now,
				unyolodoctor.DefaultCredentialRotationAge, unyolodoctor.CredentialRevocationAutomatic),
			unyolodoctor.StoredCredentialStatus("github-user-refresh:"+id, item.UpdatedAt, item.RefreshExpiresAt, now,
				unyolodoctor.DefaultCredentialRotationAge, unyolodoctor.CredentialRevocationAutomatic),
		)
	}
	return values, storedCredentialCheck(unyolodoctor.CheckPass)
}

func storedCredentialCheck(status unyolodoctor.CheckStatus) *unyolodoctor.Check {
	message := "encrypted GitHub user lifecycle metadata is valid"
	if status != unyolodoctor.CheckPass {
		message = "encrypted GitHub user lifecycle metadata could not be inspected"
	}
	return &unyolodoctor.Check{Status: status, Name: "github_user_lifecycle_metadata", Message: message}
}

func inlineCredentialChecks(cfg config.Config) []unyolodoctor.Check {
	checks := make([]unyolodoctor.Check, 0, 5)
	checks = appendInlineCredentialCheck(checks, cfg.SharedSecret != "" && cfg.SecretsFile == "", "broker_client_secret")
	checks = appendInlineCredentialCheck(checks, cfg.GitHubToken != "" && cfg.GitHubTokenFile == "", "github_token")
	checks = appendInlineCredentialCheck(checks, cfg.GitHubWebhookSecret != "" && cfg.GitHubWebhookSecretFile == "", "github_webhook_secret")
	checks = appendInlineCredentialCheck(checks, cfg.GitHubAppClientSecret != "" && cfg.GitHubAppClientSecretFile == "", "github_app_client_secret")
	checks = appendInlineCredentialCheck(checks, cfg.TelegramBotToken != "" && cfg.TelegramBotTokenFile == "", "telegram_bot_token")
	return checks
}

func appendInlineCredentialCheck(checks []unyolodoctor.Check, configured bool, credential string) []unyolodoctor.Check {
	if !configured {
		return checks
	}
	return append(checks, unyolodoctor.Check{
		Status:  unyolodoctor.CheckUnknown,
		Name:    "inline_" + credential + "_isolation",
		Message: "inline credential isolation cannot be verified; use a protected credential file",
	})
}

func githubChecks(ctx context.Context, cfg config.Config, opts Options, owner string, repo string) []unyolodoctor.Check {
	baseURL := opts.APIBaseURL
	if baseURL == nil {
		baseURL, _ = url.Parse("https://api.github.com")
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	apis, installationChecks := githubDoctorAPI(ctx, cfg, baseURL, client, owner, repo, opts.RequireProtection)
	checks := append([]unyolodoctor.Check(nil), installationChecks...)
	if apis.repository == nil {
		return checks
	}
	defaultBranch, err := apis.repository.DefaultBranch(ctx, owner, repo)
	checks = append(checks, resultCheck("github_repo_visible", "configured repository is visible", "configured repository is not visible", err))
	if err != nil {
		return checks
	}
	checks = append(checks, unyolodoctor.Check{Status: unyolodoctor.CheckPass, Name: "github_default_branch", Message: "default branch is " + defaultBranch})
	if apis.protection == nil {
		checks = append(checks, protectionCheck(opts.RequireProtection, false, errors.New("GitHub protection inspection credential is unavailable")))
		return checks
	}
	protected, protectionErr := apis.protection.BranchProtected(ctx, owner, repo, defaultBranch)
	checks = append(checks, protectionCheck(opts.RequireProtection, protected, protectionErr))
	return checks
}

type doctorAPIs struct {
	repository *githubauth.API
	protection *githubauth.API
}

func githubDoctorAPI(ctx context.Context, cfg config.Config, baseURL *url.URL, client *http.Client, owner string, repo string, requireProtection bool) (doctorAPIs, []unyolodoctor.Check) {
	var webURL *url.URL
	if strings.TrimSpace(cfg.GitHubWebBaseURL) != "" {
		var err error
		webURL, err = url.Parse(cfg.GitHubWebBaseURL)
		if err != nil {
			return doctorAPIs{}, []unyolodoctor.Check{resultCheck("github_credentials", "GitHub credential provider is configured", "GitHub credential provider is invalid", err)}
		}
	}
	manager, err := githubauth.New(githubauth.Config{AppID: cfg.GitHubAppID, AppPrivateKey: cfg.GitHubAppPrivateKey,
		AppClientID: cfg.GitHubAppClientID, AppClientSecret: []byte(cfg.GitHubAppClientSecret), DevelopmentToken: []byte(cfg.GitHubToken),
		DevelopmentTokenFile: cfg.GitHubTokenFile, APIBaseURL: baseURL, WebBaseURL: webURL, HTTPClient: client})
	if err != nil {
		return doctorAPIs{}, []unyolodoctor.Check{resultCheck("github_credentials", "GitHub credential provider is configured", "GitHub credential provider is invalid", err)}
	}
	if manager.CredentialKind() == githubauth.KindDevelopmentToken {
		return developmentDoctorAPI(ctx, cfg.Environment, manager, owner, repo)
	}
	return appDoctorAPI(ctx, manager, owner, repo, requireProtection)
}

func developmentDoctorAPI(ctx context.Context, environment string, manager *githubauth.Manager, owner, repo string) (doctorAPIs, []unyolodoctor.Check) {
	status := unyolodoctor.CheckWarn
	message := "development-token fallback is non-production and cannot prove GitHub App permission narrowing"
	if strings.EqualFold(environment, "production") || strings.EqualFold(environment, "prod") {
		status = unyolodoctor.CheckFail
		message = "development-token fallback must not be used in production"
	}
	check := unyolodoctor.Check{Status: status, Name: "github_development_token", Message: message}
	credential, err := manager.RepositoryCredential(ctx, "repo.contents.read", owner, repo)
	if err != nil {
		return doctorAPIs{}, []unyolodoctor.Check{check, resultCheck("github_credentials", "development credential is usable", "development credential is unavailable", err)}
	}
	api, err := manager.API(credential)
	if err != nil {
		return doctorAPIs{}, []unyolodoctor.Check{check, resultCheck("github_credentials", "development credential is usable", "development credential is unavailable", err)}
	}
	return doctorAPIs{repository: api, protection: api}, []unyolodoctor.Check{check}
}

func appDoctorAPI(ctx context.Context, manager *githubauth.Manager, owner, repo string, requireProtection bool) (doctorAPIs, []unyolodoctor.Check) {
	jwtErr := manager.CheckApp(ctx)
	checks := []unyolodoctor.Check{resultCheck("github_app_jwt", "GitHub App authenticated transport works", "GitHub App authenticated transport failed", jwtErr)}
	if jwtErr != nil {
		return doctorAPIs{}, checks
	}
	credential, tokenErr := manager.RepositoryCredential(ctx, "repo.contents.read", owner, repo)
	checks = append(checks, resultCheck("github_installation_token", "exact repository installation token can be minted", "exact repository installation token cannot be minted", tokenErr))
	if tokenErr != nil {
		return doctorAPIs{}, checks
	}
	checks = append(checks, permissionCheck(credential.Metadata().Permissions))
	api, apiErr := manager.API(credential)
	if apiErr != nil {
		return doctorAPIs{}, append(checks, resultCheck("github_api_client", "GitHub API client is ready", "GitHub API client is unavailable", apiErr))
	}
	if !requireProtection {
		return doctorAPIs{repository: api}, checks
	}
	protectionCredential, protectionTokenErr := manager.RepositoryCredential(ctx, "branch_protection.repos_get_branch_protection", owner, repo)
	checks = append(checks, resultCheck("github_protection_token", "exact repository protection token can be minted", "exact repository protection token cannot be minted", protectionTokenErr))
	if protectionTokenErr != nil {
		return doctorAPIs{repository: api}, checks
	}
	checks = append(checks, protectionPermissionCheck(protectionCredential.Metadata().Permissions))
	protectionAPI, protectionAPIErr := manager.API(protectionCredential)
	if protectionAPIErr != nil {
		checks = append(checks, resultCheck("github_protection_api_client", "GitHub protection API client is ready", "GitHub protection API client is unavailable", protectionAPIErr))
		return doctorAPIs{repository: api}, checks
	}
	return doctorAPIs{repository: api, protection: protectionAPI}, checks
}

func permissionCheck(permissions map[string]string) unyolodoctor.Check {
	return exactPermissionCheck(permissions, "contents", "github_app_permissions", "repository inspection credential", "contents read")
}

func protectionPermissionCheck(permissions map[string]string) unyolodoctor.Check {
	return exactPermissionCheck(permissions, "administration", "github_protection_permissions", "protection inspection credential", "administration read")
}

func exactPermissionCheck(permissions map[string]string, permission, name, subject, scope string) unyolodoctor.Check {
	if len(permissions) != 1 || permissions[permission] != "read" {
		return unyolodoctor.Check{Status: unyolodoctor.CheckFail, Name: name, Message: subject + " was not narrowed to " + scope}
	}
	return unyolodoctor.Check{Status: unyolodoctor.CheckPass, Name: name, Message: subject + " is narrowed to " + scope}
}

func protectionCheck(required bool, protected bool, err error) unyolodoctor.Check {
	if protected {
		return unyolodoctor.Check{Status: unyolodoctor.CheckPass, Name: "github_default_branch_protected", Message: "default branch has an applicable ruleset or branch protection"}
	}
	if !required {
		return unyolodoctor.Check{Status: unyolodoctor.CheckWarn, Name: "github_default_branch_protected", Message: "default branch protection was not required by this doctor run"}
	}
	if code, statusError := githubauth.StatusCode(err); err != nil && (!statusError || code != http.StatusNotFound) {
		return unyolodoctor.Check{Status: unyolodoctor.CheckUnknown, Name: "github_default_branch_protected", Message: "default branch protection could not be inspected with the configured credential"}
	}
	return unyolodoctor.Check{Status: unyolodoctor.CheckFail, Name: "github_default_branch_protected", Message: "default branch has no verifiable ruleset or branch protection"}
}

func resultCheck(name string, passMessage string, failMessage string, err error) unyolodoctor.Check {
	if err != nil {
		return unyolodoctor.Check{Status: unyolodoctor.CheckFail, Name: name, Message: failMessage}
	}
	return unyolodoctor.Check{Status: unyolodoctor.CheckPass, Name: name, Message: passMessage}
}

func parseRepo(value string) (string, string, error) {
	owner, repo, ok := strings.Cut(strings.TrimSpace(value), "/")
	if !ok || owner == "" || repo == "" || strings.Contains(repo, "/") {
		return "", "", errors.New("repo must be owner/name")
	}
	return owner, repo, nil
}
