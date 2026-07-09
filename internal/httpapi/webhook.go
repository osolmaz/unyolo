package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/brokerkit/httpx"
)

const maxWebhookBodyBytes int64 = 1024 * 1024

type githubWebhookMetadata struct {
	Event          string
	Delivery       string
	Action         string
	InstallationID int64
	Repository     string
}

func (s *Server) githubWebhook(c echo.Context) error {
	if strings.TrimSpace(s.githubWebhookSecret) == "" {
		return echo.NewHTTPError(http.StatusNotFound, "github webhook is not configured")
	}
	body, err := httpx.ReadLimited(c.Request().Body, maxWebhookBodyBytes)
	if err != nil {
		return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "github webhook body is too large")
	}
	metadata, err := verifyGitHubWebhook(c.Request().Header, body, s.githubWebhookSecret)
	if err != nil {
		return err
	}
	s.auditGitHubWebhook(metadata)
	return c.JSON(http.StatusAccepted, map[string]string{"status": "accepted"})
}

func verifyGitHubWebhook(header http.Header, body []byte, secret string) (githubWebhookMetadata, error) {
	metadata, err := githubWebhookHeaders(header)
	if err != nil {
		return githubWebhookMetadata{}, err
	}
	if !validWebhookSignature(header.Get("X-Hub-Signature-256"), body, secret) {
		return githubWebhookMetadata{}, echo.NewHTTPError(http.StatusUnauthorized, "invalid github webhook signature")
	}
	bodyMetadata, err := githubWebhookBodyMetadata(body)
	if err != nil {
		return githubWebhookMetadata{}, err
	}
	metadata.Action = bodyMetadata.Action
	metadata.InstallationID = bodyMetadata.InstallationID
	metadata.Repository = bodyMetadata.Repository
	return metadata, nil
}

func githubWebhookHeaders(header http.Header) (githubWebhookMetadata, error) {
	event := strings.TrimSpace(header.Get("X-GitHub-Event"))
	delivery := strings.TrimSpace(header.Get("X-GitHub-Delivery"))
	signature := strings.TrimSpace(header.Get("X-Hub-Signature-256"))
	switch {
	case event == "":
		return githubWebhookMetadata{}, echo.NewHTTPError(http.StatusBadRequest, "missing X-GitHub-Event")
	case delivery == "":
		return githubWebhookMetadata{}, echo.NewHTTPError(http.StatusBadRequest, "missing X-GitHub-Delivery")
	case signature == "":
		return githubWebhookMetadata{}, echo.NewHTTPError(http.StatusBadRequest, "missing X-Hub-Signature-256")
	default:
		return githubWebhookMetadata{Event: event, Delivery: delivery}, nil
	}
}

func validWebhookSignature(signature string, body []byte, secret string) bool {
	const prefix = "sha256="
	rawHex, ok := strings.CutPrefix(strings.TrimSpace(signature), prefix)
	if !ok {
		return false
	}
	got, err := hex.DecodeString(rawHex)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}

func githubWebhookBodyMetadata(body []byte) (githubWebhookMetadata, error) {
	var payload struct {
		Action       string `json:"action"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
		Repository struct {
			FullName string `json:"full_name"`
			Name     string `json:"name"`
			Owner    struct {
				Login string `json:"login"`
			} `json:"owner"`
		} `json:"repository"`
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return githubWebhookMetadata{}, echo.NewHTTPError(http.StatusBadRequest, "github webhook body is empty")
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return githubWebhookMetadata{}, echo.NewHTTPError(http.StatusBadRequest, "invalid github webhook json")
	}
	return githubWebhookMetadata{
		Action:         strings.TrimSpace(payload.Action),
		InstallationID: payload.Installation.ID,
		Repository:     webhookRepositoryName(payload.Repository.FullName, payload.Repository.Owner.Login, payload.Repository.Name),
	}, nil
}

func webhookRepositoryName(fullName string, owner string, name string) string {
	if strings.TrimSpace(fullName) != "" {
		return strings.TrimSpace(fullName)
	}
	if strings.TrimSpace(owner) == "" || strings.TrimSpace(name) == "" {
		return ""
	}
	return strings.TrimSpace(owner) + "/" + strings.TrimSpace(name)
}

func (s *Server) auditGitHubWebhook(metadata githubWebhookMetadata) {
	attrs := []any{
		"event", metadata.Event,
		"delivery", metadata.Delivery,
	}
	if metadata.Action != "" {
		attrs = append(attrs, "action", metadata.Action)
	}
	if metadata.InstallationID > 0 {
		attrs = append(attrs, "github_installation_id", strconv.FormatInt(metadata.InstallationID, 10))
	}
	if metadata.Repository != "" {
		attrs = append(attrs, "repository", metadata.Repository)
	}
	s.logger.Info("github webhook", attrs...)
}
