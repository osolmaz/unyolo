package githubauth

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/internal/strictjson"
)

func classifyHTTPError(response *http.Response) error {
	status := responseStatus(response)
	requestID := githubRequestID(response.Header)
	message := githubHTTPErrorMessage(response.Body)
	if status == http.StatusForbidden && strings.TrimSpace(response.Header.Get("Retry-After")) != "" {
		return APIError{Code: "secondary_rate_limited", StatusCode: status, Message: message, RequestID: requestID}
	}
	if status == http.StatusTooManyRequests || response.Header.Get("X-RateLimit-Remaining") == "0" {
		return APIError{Code: "rate_limited", StatusCode: status, RateReset: rateReset(response.Header), Message: message, RequestID: requestID}
	}
	if status >= http.StatusMultipleChoices && status < http.StatusBadRequest {
		return APIError{Code: "redirect_not_allowed", StatusCode: status, RequestID: requestID}
	}
	return APIError{Code: statusCodeName(status), StatusCode: status, Message: message, RequestID: requestID}
}

func githubHTTPErrorMessage(body io.Reader) string {
	data, err := limitedBody(body, 64<<10)
	if err != nil {
		return ""
	}
	var payload struct {
		Message string `json:"message"`
	}
	if strictjson.Decode(data, &payload, false) != nil {
		return ""
	}
	return safeGitHubMessage(payload.Message)
}

func githubRequestID(header http.Header) string {
	value := strings.TrimSpace(header.Get("X-GitHub-Request-Id"))
	if value == "" || len(value) > 128 || !validGitHubRequestID(value) {
		return ""
	}
	return value
}

func validGitHubRequestID(value string) bool {
	for _, char := range value {
		if !githubRequestIDCharacter(char) {
			return false
		}
	}
	return true
}

func githubRequestIDCharacter(char rune) bool {
	return char == ':' || char == '-' || char == '_' || char >= 'A' && char <= 'Z' ||
		char >= 'a' && char <= 'z' || char >= '0' && char <= '9'
}

func safeGitHubMessage(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 240 || containsSensitiveMarker(value) || containsControlCharacter(value) {
		return ""
	}
	return value
}

func containsSensitiveMarker(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"authorization:", "bearer ", "access_token", "refresh_token", "client_secret", "private_key", "password="} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func containsControlCharacter(value string) bool {
	for _, char := range value {
		if char < ' ' {
			return true
		}
	}
	return false
}

func safeGitHubCode(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || len(value) > 64 || !validGitHubCode(value) {
		return fallback
	}
	return value
}

func validGitHubCode(value string) bool {
	for _, char := range value {
		if char != '_' && char != '-' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

func rateReset(header http.Header) time.Time {
	value := strings.TrimSpace(header.Get("X-RateLimit-Reset"))
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || seconds <= 0 {
		return time.Time{}
	}
	return time.Unix(seconds, 0).UTC()
}
