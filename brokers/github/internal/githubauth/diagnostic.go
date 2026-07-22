package githubauth

import (
	"math"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxGitHubDiagnosticRunes = 500
	minOpaqueTokenLength     = 32
	minOpaqueTokenEntropy    = 3.5
	redactedDiagnosticValue  = "[redacted]"
)

var (
	githubCredentialPattern  = regexp.MustCompile(`(?i)(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})`)
	jwtPattern               = regexp.MustCompile(`[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}`)
	labeledCredentialPattern = regexp.MustCompile(`(?i)\b(?:authorization|(?:access[_-]?)?token|api[_-]?key|client[_-]?secret|password|secret)\s*[:=]\s*[^\s,;]+|\bbearer\s+[^\s,;]+`)
	urlPattern               = regexp.MustCompile(`(?i)https?://[^\s<>"']+`)
	opaqueTokenPattern       = regexp.MustCompile(`[A-Za-z0-9_+/=.~-]{32,}`)
)

func safeGitHubMessage(value string) string {
	return safeGitHubMessages([]string{value}, nil)
}

// safeGitHubResponseMessages accepts only parsed GitHub message fields. Raw
// response bodies and other provider-controlled metadata stay outside this path.
func safeGitHubResponseMessages(values []string, response *http.Response) string {
	return safeGitHubMessages(values, responseSecrets(response))
}

func safeGitHubMessages(values, secrets []string) string {
	messages := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		message := sanitizeGitHubMessage(value, secrets)
		if message == "" {
			continue
		}
		if _, duplicate := seen[message]; duplicate {
			continue
		}
		seen[message] = struct{}{}
		messages = append(messages, message)
	}
	return truncateDiagnostic(strings.Join(messages, ": "))
}

func sanitizeGitHubMessage(value string, secrets []string) string {
	if !utf8.ValidString(value) {
		return ""
	}
	value = redactExactValues(value, secrets)
	value = githubCredentialPattern.ReplaceAllString(value, redactedDiagnosticValue)
	value = jwtPattern.ReplaceAllString(value, redactedDiagnosticValue)
	value = labeledCredentialPattern.ReplaceAllString(value, redactedDiagnosticValue)
	value = urlPattern.ReplaceAllString(value, "[url]")
	value = opaqueTokenPattern.ReplaceAllStringFunc(value, redactOpaqueToken)
	return truncateDiagnostic(normalizeDiagnostic(value))
}

func responseSecrets(response *http.Response) []string {
	if response == nil || response.Request == nil {
		return nil
	}
	authorization := strings.TrimSpace(response.Request.Header.Get("Authorization"))
	if authorization == "" {
		return nil
	}
	values := []string{authorization}
	if _, credential, found := strings.Cut(authorization, " "); found {
		credential = strings.TrimSpace(credential)
		if credential != "" {
			values = append(values, credential)
		}
	}
	return values
}

func redactExactValues(value string, secrets []string) string {
	secrets = append([]string(nil), secrets...)
	sort.Slice(secrets, func(left, right int) bool { return len(secrets[left]) > len(secrets[right]) })
	for _, secret := range secrets {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, redactedDiagnosticValue)
		}
	}
	return value
}

// redactOpaqueToken catches future opaque credential formats without maintaining
// a provider-message allowlist. Git revision digests remain useful diagnostics.
func redactOpaqueToken(value string) string {
	if len(value) < minOpaqueTokenLength || hexadecimalDigest(value) || shannonEntropy(value) < minOpaqueTokenEntropy {
		return value
	}
	return redactedDiagnosticValue
}

func hexadecimalDigest(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, char := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF", char) {
			return false
		}
	}
	return true
}

func shannonEntropy(value string) float64 {
	counts := make(map[rune]int)
	var total int
	for _, char := range value {
		counts[char]++
		total++
	}
	if total == 0 {
		return 0
	}
	var entropy float64
	for _, count := range counts {
		probability := float64(count) / float64(total)
		entropy -= probability * math.Log2(probability)
	}
	return entropy
}

func normalizeDiagnostic(value string) string {
	var output strings.Builder
	space := false
	for _, char := range value {
		if unicode.IsSpace(char) {
			space = output.Len() > 0
			continue
		}
		if !unicode.IsPrint(char) {
			continue
		}
		if space {
			output.WriteByte(' ')
			space = false
		}
		output.WriteRune(char)
	}
	return strings.TrimSpace(output.String())
}

func truncateDiagnostic(value string) string {
	if utf8.RuneCountInString(value) <= maxGitHubDiagnosticRunes {
		return value
	}
	runes := []rune(value)
	return strings.TrimSpace(string(runes[:maxGitHubDiagnosticRunes-1])) + "…"
}
