package githubauth

import (
	"errors"
	"net/http"
	"strings"

	github "github.com/google/go-github/v88/github"
)

var (
	ErrWebhookInvalid   = errors.New("GitHub webhook is invalid")
	ErrWebhookSignature = errors.New("GitHub webhook signature is invalid")
)

type WebhookEvent struct {
	Event                  string
	Delivery               string
	Action                 string
	InstallationID         int64
	Repository             string
	RevokedUserID          int64
	DisableInstallation    bool
	EnableInstallation     bool
	InvalidateInstallation bool
}

func ParseWebhook(header http.Header, body []byte, secret []byte) (WebhookEvent, error) {
	event := strings.TrimSpace(header.Get("X-GitHub-Event"))
	delivery := strings.TrimSpace(header.Get("X-GitHub-Delivery"))
	signature := strings.TrimSpace(header.Get("X-Hub-Signature-256"))
	if event == "" || delivery == "" || signature == "" || len(body) == 0 || len(secret) == 0 {
		return WebhookEvent{}, ErrWebhookInvalid
	}
	if err := github.ValidateSignature(signature, body, secret); err != nil {
		return WebhookEvent{}, ErrWebhookSignature
	}
	parsed, err := github.ParseWebHook(event, body)
	if err != nil {
		return WebhookEvent{}, ErrWebhookInvalid
	}
	result := WebhookEvent{Event: event, Delivery: delivery}
	populateWebhookEvent(&result, parsed)
	return result, nil
}

func populateWebhookEvent(result *WebhookEvent, parsed any) {
	switch payload := parsed.(type) {
	case *github.InstallationEvent:
		populateInstallationEvent(result, payload)
	case *github.InstallationRepositoriesEvent:
		populateInstallationRepositoriesEvent(result, payload)
	case *github.InstallationTargetEvent:
		populateRepositoryEvent(result, payload.GetAction(), payload.GetInstallation().GetID(), payload.GetRepository())
	case *github.GitHubAppAuthorizationEvent:
		populateAuthorizationEvent(result, payload)
	case *github.RepositoryEvent:
		populateRepositoryEvent(result, payload.GetAction(), payload.GetInstallation().GetID(), payload.GetRepo())
	default:
		result.Action = actionFromEvent(payload)
	}
}

func populateInstallationEvent(result *WebhookEvent, payload *github.InstallationEvent) {
	result.Action = payload.GetAction()
	result.InstallationID = payload.GetInstallation().GetID()
	result.InvalidateInstallation = result.InstallationID > 0
	result.DisableInstallation = result.Action == "deleted" || result.Action == "suspend"
	result.EnableInstallation = result.Action == "created" || result.Action == "unsuspend"
}

func populateInstallationRepositoriesEvent(result *WebhookEvent, payload *github.InstallationRepositoriesEvent) {
	result.Action = payload.GetAction()
	result.InstallationID = payload.GetInstallation().GetID()
	result.InvalidateInstallation = result.InstallationID > 0
	result.Repository = repositoryName(firstRepository(payload.GetRepositoriesAdded(), payload.GetRepositoriesRemoved()))
}

func populateRepositoryEvent(result *WebhookEvent, action string, installationID int64, repository *github.Repository) {
	result.Action = action
	result.InstallationID = installationID
	result.InvalidateInstallation = installationID > 0
	result.Repository = repositoryName(repository)
}

func populateAuthorizationEvent(result *WebhookEvent, payload *github.GitHubAppAuthorizationEvent) {
	result.Action = payload.GetAction()
	if result.Action == "revoked" {
		result.RevokedUserID = payload.GetSender().GetID()
	}
}

func firstRepository(groups ...[]*github.Repository) *github.Repository {
	for _, group := range groups {
		if len(group) > 0 {
			return group[0]
		}
	}
	return nil
}

func repositoryName(repository *github.Repository) string {
	if repository == nil {
		return ""
	}
	if repository.GetFullName() != "" {
		return repository.GetFullName()
	}
	if repository.GetOwner().GetLogin() == "" || repository.GetName() == "" {
		return ""
	}
	return repository.GetOwner().GetLogin() + "/" + repository.GetName()
}

func actionFromEvent(event any) string {
	if value, ok := event.(interface{ GetAction() string }); ok {
		return value.GetAction()
	}
	return ""
}
