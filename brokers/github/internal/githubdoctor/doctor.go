// Package githubdoctor verifies local isolation and GitHub-native enforcement.
package githubdoctor

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/brokers/github/internal/config"
	"github.com/osolmaz/brokerkit/brokers/github/internal/githubauth"
	bkdoctor "github.com/osolmaz/brokerkit/doctor"
)

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
	paths := []string{cfg.GitHubTokenFile, cfg.GitHubAppPrivateKeyFile, cfg.GitHubAppClientSecretFile, cfg.GitHubWebhookSecretFile, cfg.SecretsFile, cfg.TelegramBotTokenFile}
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
	checks := make([]bkdoctor.Check, 0, 5)
	checks = appendInlineCredentialCheck(checks, cfg.SharedSecret != "" && cfg.SecretsFile == "", "broker_client_secret")
	checks = appendInlineCredentialCheck(checks, cfg.GitHubToken != "" && cfg.GitHubTokenFile == "", "github_token")
	checks = appendInlineCredentialCheck(checks, cfg.GitHubWebhookSecret != "" && cfg.GitHubWebhookSecretFile == "", "github_webhook_secret")
	checks = appendInlineCredentialCheck(checks, cfg.GitHubAppClientSecret != "" && cfg.GitHubAppClientSecretFile == "", "github_app_client_secret")
	checks = appendInlineCredentialCheck(checks, cfg.TelegramBotToken != "" && cfg.TelegramBotTokenFile == "", "telegram_bot_token")
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
	apis, installationChecks := githubDoctorAPI(ctx, cfg, baseURL, client, owner, repo, opts.RequireProtection)
	checks := append([]bkdoctor.Check(nil), installationChecks...)
	if apis.repository == nil {
		return checks
	}
	defaultBranch, err := apis.repository.DefaultBranch(ctx, owner, repo)
	checks = append(checks, resultCheck("github_repo_visible", "configured repository is visible", "configured repository is not visible", err))
	if err != nil {
		return checks
	}
	checks = append(checks, bkdoctor.Check{Status: bkdoctor.CheckPass, Name: "github_default_branch", Message: "default branch is " + defaultBranch})
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

func githubDoctorAPI(ctx context.Context, cfg config.Config, baseURL *url.URL, client *http.Client, owner string, repo string, requireProtection bool) (doctorAPIs, []bkdoctor.Check) {
	var webURL *url.URL
	if strings.TrimSpace(cfg.GitHubWebBaseURL) != "" {
		var err error
		webURL, err = url.Parse(cfg.GitHubWebBaseURL)
		if err != nil {
			return doctorAPIs{}, []bkdoctor.Check{resultCheck("github_credentials", "GitHub credential provider is configured", "GitHub credential provider is invalid", err)}
		}
	}
	manager, err := githubauth.New(githubauth.Config{AppID: cfg.GitHubAppID, AppPrivateKey: cfg.GitHubAppPrivateKey,
		AppClientID: cfg.GitHubAppClientID, AppClientSecret: []byte(cfg.GitHubAppClientSecret), DevelopmentToken: []byte(cfg.GitHubToken),
		DevelopmentTokenFile: cfg.GitHubTokenFile, APIBaseURL: baseURL, WebBaseURL: webURL, HTTPClient: client})
	if err != nil {
		return doctorAPIs{}, []bkdoctor.Check{resultCheck("github_credentials", "GitHub credential provider is configured", "GitHub credential provider is invalid", err)}
	}
	if manager.CredentialKind() == githubauth.KindDevelopmentToken {
		return developmentDoctorAPI(ctx, cfg.Environment, manager, owner, repo)
	}
	return appDoctorAPI(ctx, manager, owner, repo, requireProtection)
}

func developmentDoctorAPI(ctx context.Context, environment string, manager *githubauth.Manager, owner, repo string) (doctorAPIs, []bkdoctor.Check) {
	status := bkdoctor.CheckWarn
	message := "development-token fallback is non-production and cannot prove GitHub App permission narrowing"
	if strings.EqualFold(environment, "production") || strings.EqualFold(environment, "prod") {
		status = bkdoctor.CheckFail
		message = "development-token fallback must not be used in production"
	}
	check := bkdoctor.Check{Status: status, Name: "github_development_token", Message: message}
	credential, err := manager.RepositoryCredential(ctx, "repo.contents.read", owner, repo)
	if err != nil {
		return doctorAPIs{}, []bkdoctor.Check{check, resultCheck("github_credentials", "development credential is usable", "development credential is unavailable", err)}
	}
	api, err := manager.API(credential)
	if err != nil {
		return doctorAPIs{}, []bkdoctor.Check{check, resultCheck("github_credentials", "development credential is usable", "development credential is unavailable", err)}
	}
	return doctorAPIs{repository: api, protection: api}, []bkdoctor.Check{check}
}

func appDoctorAPI(ctx context.Context, manager *githubauth.Manager, owner, repo string, requireProtection bool) (doctorAPIs, []bkdoctor.Check) {
	jwtErr := manager.CheckApp(ctx)
	checks := []bkdoctor.Check{resultCheck("github_app_jwt", "GitHub App authenticated transport works", "GitHub App authenticated transport failed", jwtErr)}
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

func permissionCheck(permissions map[string]string) bkdoctor.Check {
	if len(permissions) != 1 || permissions["contents"] != "read" {
		return bkdoctor.Check{Status: bkdoctor.CheckFail, Name: "github_app_permissions", Message: "repository inspection credential was not narrowed to contents read"}
	}
	return bkdoctor.Check{Status: bkdoctor.CheckPass, Name: "github_app_permissions", Message: "repository inspection credential is narrowed to contents read"}
}

func protectionPermissionCheck(permissions map[string]string) bkdoctor.Check {
	if len(permissions) != 1 || permissions["administration"] != "read" {
		return bkdoctor.Check{Status: bkdoctor.CheckFail, Name: "github_protection_permissions", Message: "protection inspection credential was not narrowed to administration read"}
	}
	return bkdoctor.Check{Status: bkdoctor.CheckPass, Name: "github_protection_permissions", Message: "protection inspection credential is narrowed to administration read"}
}

func protectionCheck(required bool, protected bool, err error) bkdoctor.Check {
	if protected {
		return bkdoctor.Check{Status: bkdoctor.CheckPass, Name: "github_default_branch_protected", Message: "default branch has an applicable ruleset or branch protection"}
	}
	if !required {
		return bkdoctor.Check{Status: bkdoctor.CheckWarn, Name: "github_default_branch_protected", Message: "default branch protection was not required by this doctor run"}
	}
	if code, statusError := githubauth.StatusCode(err); err != nil && (!statusError || code != http.StatusNotFound) {
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
