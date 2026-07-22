package githubauth

import (
	"net/http"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestSafeGitHubMessagePreservesDocumentedDeveloperDiagnostics(t *testing.T) {
	t.Parallel()
	for input, expected := range map[string]string{
		"No commit found for the ref feature/missing":                                                      "No commit found for the ref feature/missing",
		"Argument 'number' on Field 'pullRequest' has an invalid value (\"wrong\"). Expected type 'Int!'.": "Argument 'number' on Field 'pullRequest' has an invalid value (\"wrong\"). Expected type 'Int!'.",
		"Merge commits are not allowed on this repository.":                                                "Merge commits are not allowed on this repository.",
		"first\n\tsecond\u202ethird":                                                                       "first secondthird",
	} {
		if got := safeGitHubMessage(input); got != expected {
			t.Fatalf("safeGitHubMessage(%q) = %q, want %q", input, got, expected)
		}
	}
}

func TestSafeGitHubMessageRedactsCredentialLikeValues(t *testing.T) {
	t.Parallel()
	canaries := []string{
		"gh" + "p_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
		"github_" + "pat_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
		strings.Join([]string{"eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJicm9rZXJraXQifQ", "c2lnbmF0dXJlMTIzNDU2"}, "."),
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz",
	}
	messages := []string{
		"No commit found for the ref " + canaries[0],
		"token=" + canaries[1] + " was rejected",
		"Bearer " + canaries[2] + " is invalid",
		"Opaque value " + canaries[3] + " failed",
		"See https://example.test/path?access_token=" + canaries[0],
		"access_token=short-secret-value is invalid",
	}
	for _, message := range messages {
		got := safeGitHubMessage(message)
		if got == "" || !strings.Contains(got, redactedDiagnosticValue) && !strings.Contains(got, "[url]") {
			t.Fatalf("diagnostic was not usefully redacted: %q", got)
		}
		for _, canary := range canaries {
			if strings.Contains(got, canary) {
				t.Fatalf("diagnostic retained credential canary %q: %q", canary, got)
			}
		}
	}
}

func TestSafeGitHubResponseMessageRedactsExactRequestCredential(t *testing.T) {
	t.Parallel()
	const credential = "opaque-but-short-credential"
	request, err := http.NewRequest(http.MethodPost, "https://api.github.test/graphql", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+credential)
	response := &http.Response{Request: request}
	message := safeGitHubResponseMessages([]string{"GitHub repeated " + credential}, response)
	if strings.Contains(message, credential) || message != "GitHub repeated "+redactedDiagnosticValue {
		t.Fatalf("exact request credential was not redacted: %q", message)
	}
}

func TestSafeGitHubMessageBoundsAndNormalizesOutput(t *testing.T) {
	t.Parallel()
	message := safeGitHubMessages([]string{"same message", "same message", strings.Repeat("界", 800)}, nil)
	if !utf8.ValidString(message) || utf8.RuneCountInString(message) > maxGitHubDiagnosticRunes || !strings.HasSuffix(message, "…") {
		t.Fatalf("bounded message is invalid: runes=%d suffix=%q", utf8.RuneCountInString(message), message[len(message)-3:])
	}
	for _, char := range message {
		if unicode.IsControl(char) || unicode.Is(unicode.Cf, char) {
			t.Fatalf("message retained unsafe Unicode %U", char)
		}
	}
	if safeGitHubMessage(string([]byte{0xff, 0xfe})) != "" {
		t.Fatal("invalid UTF-8 diagnostic was retained")
	}
}

func TestSafeGitHubMessagePreservesRevisionDigests(t *testing.T) {
	t.Parallel()
	for _, digest := range []string{strings.Repeat("a", 40), strings.Repeat("b", 64)} {
		message := safeGitHubMessage("Revision " + digest + " is stale")
		if !strings.Contains(message, digest) {
			t.Fatalf("revision digest was redacted: %q", message)
		}
	}
}

func FuzzSafeGitHubMessage(f *testing.F) {
	for _, seed := range []string{
		"Merge commits are not allowed on this repository.",
		"No commit found for the ref " + "gh" + "p_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
		"line one\nline two\u202e",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		message := safeGitHubMessage(input)
		if !utf8.ValidString(message) || utf8.RuneCountInString(message) > maxGitHubDiagnosticRunes {
			t.Fatalf("invalid diagnostic bounds: %q", message)
		}
		for _, char := range message {
			if unicode.IsControl(char) || unicode.Is(unicode.Cf, char) {
				t.Fatalf("unsafe diagnostic Unicode %U", char)
			}
		}
	})
}
