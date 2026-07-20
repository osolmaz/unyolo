package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/brokerkit/brokers/github/internal/githubauth"
	"github.com/osolmaz/brokerkit/brokers/github/internal/policy"
	"github.com/osolmaz/brokerkit/telemetry/audit"
	"github.com/osolmaz/brokerkit/transport/http"
)

const maxWebhookBodyBytes int64 = 1024 * 1024

type githubWebhookMetadata = githubauth.WebhookEvent

func (s *Server) githubWebhook(c echo.Context) error {
	if strings.TrimSpace(s.githubWebhookSecret) == "" {
		return echo.NewHTTPError(http.StatusNotFound, "github webhook is not configured")
	}
	body, err := httpx.ReadLimited(c.Request().Body, maxWebhookBodyBytes)
	if err != nil {
		return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "github webhook body is too large")
	}
	metadata, err := githubauth.ParseWebhook(c.Request().Header, body, []byte(s.githubWebhookSecret))
	if err != nil {
		if errors.Is(err, githubauth.ErrWebhookSignature) {
			return echo.NewHTTPError(http.StatusUnauthorized, "invalid github webhook signature")
		}
		return echo.NewHTTPError(http.StatusBadRequest, "invalid github webhook")
	}
	if err := s.applyGitHubWebhook(metadata); err != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "github webhook invalidation failed")
	}
	s.auditGitHubWebhook(metadata)
	return c.JSON(http.StatusAccepted, map[string]string{"status": "accepted"})
}

func (s *Server) applyGitHubWebhook(metadata githubauth.WebhookEvent) error {
	if metadata.EnableInstallation {
		s.githubCredentials.EnableInstallation(metadata.InstallationID)
	}
	if metadata.InvalidateInstallation {
		s.githubCredentials.InvalidateInstallation(metadata.InstallationID, metadata.DisableInstallation)
	}
	if metadata.RevokedUserID > 0 {
		return s.githubCredentials.InvalidateUser(metadata.RevokedUserID)
	}
	return nil
}

func (s *Server) auditGitHubWebhook(metadata githubWebhookMetadata) {
	event := audit.Event{
		Broker: "gh-broker", Operation: string(policy.OperationWebhookGitHubReceive), Target: metadata.Repository, Decision: "received",
		Extensions: map[string]string{"github_event": metadata.Event, "github_delivery": metadata.Delivery},
	}
	if metadata.Action != "" {
		event.Extensions["github_action"] = metadata.Action
	}
	if metadata.InstallationID > 0 {
		event.Extensions["github_installation_id"] = strconv.FormatInt(metadata.InstallationID, 10)
	}
	if metadata.RevokedUserID > 0 {
		event.Extensions["github_user_id"] = strconv.FormatInt(metadata.RevokedUserID, 10)
	}
	_ = s.auditWriter.Record(event)
}
