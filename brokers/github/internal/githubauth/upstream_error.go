package githubauth

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/osolmaz/unyolo/internal/strictjson"
)

func classifyHTTPError(response *http.Response) error {
	status := responseStatus(response)
	requestID := githubRequestID(response.Header)
	message := githubHTTPErrorMessage(response)
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

func githubHTTPErrorMessage(response *http.Response) string {
	data, err := limitedBody(response.Body, 64<<10)
	if err != nil {
		return ""
	}
	var payload struct {
		Message string            `json:"message"`
		Errors  []json.RawMessage `json:"errors"`
	}
	if strictjson.Decode(data, &payload, false) != nil {
		return ""
	}
	messages := []string{payload.Message}
	for _, detail := range payload.Errors {
		if message := restErrorDetailMessage(detail); message != "" {
			messages = append(messages, message)
		}
	}
	return safeGitHubResponseMessages(messages, response)
}

func restErrorDetailMessage(data json.RawMessage) string {
	var message string
	if json.Unmarshal(data, &message) == nil {
		return message
	}
	var detail struct {
		Message string `json:"message"`
	}
	if strictjson.Decode(data, &detail, false) != nil {
		return ""
	}
	return detail.Message
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
	return char <= unicode.MaxASCII && (unicode.IsUpper(char) || unicode.IsDigit(char) || strings.ContainsRune(":-", char))
}

var publicGitHubCodes = map[string]string{
	"forbidden":           "forbidden",
	"insufficient_scopes": "insufficient_scopes",
	"not_found":           "not_found",
	"rate_limited":        "rate_limited",
	"unprocessable":       "unprocessable",
}

func safeGitHubCode(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if code, found := publicGitHubCodes[value]; found {
		return code
	}
	return fallback
}

func rateReset(header http.Header) time.Time {
	value := strings.TrimSpace(header.Get("X-RateLimit-Reset"))
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || seconds <= 0 {
		return time.Time{}
	}
	return time.Unix(seconds, 0).UTC()
}
