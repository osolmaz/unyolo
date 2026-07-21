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

var publicGitHubMessages = map[string]string{
	"pull request is not mergeable":             "Pull Request is not mergeable",
	"validation failed":                         "Validation Failed",
	"resource not accessible by integration":    "Resource not accessible by integration",
	"repository access blocked":                 "Repository access blocked",
	"bad credentials":                           "Bad credentials",
	"not found":                                 "Not Found",
	"required status checks have not succeeded": "Required status checks have not succeeded",
}

func safeGitHubMessage(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return publicGitHubMessages[value]
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
