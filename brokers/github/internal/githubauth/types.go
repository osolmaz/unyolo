// Package githubauth owns every GitHub credential used by gh-broker.
// Credentials are opaque outside this package and have no readback API.
package githubauth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	github "github.com/google/go-github/v88/github"
)

const APIVersion = "2026-03-10"

type Kind string

const (
	KindAppJWT           Kind = "app-jwt"
	KindInstallation     Kind = "installation"
	KindUser             Kind = "user"
	KindDevelopmentToken Kind = "development-token" // #nosec G101 -- credential kind, not a credential.
)

type Metadata struct {
	Kind                  Kind
	InstallationID        int64
	RepositoryIDs         []int64
	Permissions           map[string]string
	AllowEmptyPermissions bool
	UserID                int64
	APIHost               string
	ExpiresAt             time.Time
}

// Credential can authorize an upstream request without exposing its value.
type Credential struct {
	metadata Metadata
	mu       sync.RWMutex
	token    []byte
}

func lockedMapValue[K comparable, V any](mu *sync.Mutex, values map[K]V, key K) V {
	mu.Lock()
	defer mu.Unlock()
	return values[key]
}

func (c *Credential) Metadata() Metadata {
	if c == nil {
		return Metadata{}
	}
	result := c.metadata
	result.RepositoryIDs = slices.Clone(result.RepositoryIDs)
	result.Permissions = clonePermissions(result.Permissions)
	return result
}

func (c *Credential) AuthorizeAPI(request *http.Request) error {
	if request == nil {
		return errors.New("GitHub credential is unavailable")
	}
	token, err := c.tokenCopy()
	if err != nil {
		return err
	}
	defer zero(token)
	request.Header.Set("Authorization", "Bearer "+string(token))
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", APIVersion)
	return nil
}

func (c *Credential) AuthorizeGit(request *http.Request) error {
	if request == nil {
		return errors.New("GitHub credential is unavailable")
	}
	token, err := c.tokenCopy()
	if err != nil {
		return err
	}
	defer zero(token)
	encoded := base64.StdEncoding.EncodeToString(append([]byte("x-access-token:"), token...))
	request.Header.Set("Authorization", "Basic "+encoded)
	return nil
}

func (c *Credential) tokenCopy() ([]byte, error) {
	if c == nil {
		return nil, errors.New("GitHub credential is unavailable")
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.token) == 0 || bytes.IndexFunc(c.token, unicode.IsSpace) >= 0 {
		return nil, errors.New("GitHub credential is unavailable")
	}
	return append([]byte(nil), c.token...), nil
}

func (c *Credential) invalidate() {
	if c == nil {
		return
	}
	c.mu.Lock()
	zero(c.token)
	c.token = nil
	c.mu.Unlock()
}

type APIError struct {
	Code       string
	StatusCode int
	RateReset  time.Time
	Message    string
	RequestID  string
}

func (e APIError) Error() string {
	if e.StatusCode > 0 {
		return fmt.Sprintf("GitHub API request failed (%s, status %d)", e.Code, e.StatusCode)
	}
	return "GitHub API request failed (" + e.Code + ")"
}

func StatusCode(err error) (int, bool) {
	var apiErr APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode == 0 {
		return 0, false
	}
	return apiErr.StatusCode, true
}

func IsNotFound(err error) bool {
	status, ok := StatusCode(err)
	return ok && status == http.StatusNotFound
}

func classifyAPIError(err error) error {
	if err == nil {
		return nil
	}
	var rateLimit *github.RateLimitError
	if errors.As(err, &rateLimit) {
		return APIError{Code: "rate_limited", StatusCode: responseStatus(rateLimit.Response), RateReset: rateLimit.Rate.Reset.UTC(),
			RequestID: responseRequestID(rateLimit.Response)}
	}
	var abuse *github.AbuseRateLimitError
	if errors.As(err, &abuse) {
		return APIError{Code: "secondary_rate_limited", StatusCode: responseStatus(abuse.Response), RequestID: responseRequestID(abuse.Response)}
	}
	var responseError *github.ErrorResponse
	if errors.As(err, &responseError) {
		status := responseStatus(responseError.Response)
		return APIError{Code: statusCodeName(status), StatusCode: status, Message: safeGitHubMessage(responseError.Message),
			RequestID: responseRequestID(responseError.Response)}
	}
	var apiErr APIError
	if errors.As(err, &apiErr) {
		return apiErr
	}
	return APIError{Code: "unavailable"}
}

func responseRequestID(response *http.Response) string {
	if response == nil {
		return ""
	}
	return githubRequestID(response.Header)
}

func responseStatus(response *http.Response) int {
	if response == nil {
		return 0
	}
	return response.StatusCode
}

func statusCodeName(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	case http.StatusUnprocessableEntity:
		return "validation_failed"
	case http.StatusTooManyRequests:
		return "rate_limited"
	default:
		return "upstream_error"
	}
}

func normalizeAPIURL(value *url.URL) (*url.URL, error) {
	if value == nil {
		value, _ = url.Parse("https://api.github.com/")
	}
	result := *value
	if err := validateAPIURL(result); err != nil {
		return nil, err
	}
	if !strings.HasSuffix(result.Path, "/") {
		result.Path += "/"
	}
	return &result, nil
}

func validateAPIURL(value url.URL) error {
	if !validAPIScheme(value.Scheme) {
		return errors.New("GitHub API URL must use HTTP or HTTPS")
	}
	if insecureRemoteAPIURL(value) {
		return errors.New("GitHub API URL must use HTTPS")
	}
	if invalidAPIURLParts(value) {
		return errors.New("GitHub API URL is invalid")
	}
	return nil
}

func validAPIScheme(scheme string) bool {
	return scheme == "https" || scheme == "http"
}

func insecureRemoteAPIURL(value url.URL) bool {
	return value.Scheme == "http" && !localHostname(value.Hostname())
}

func invalidAPIURLParts(value url.URL) bool {
	return value.Host == "" || value.User != nil || value.RawQuery != "" || value.Fragment != ""
}

func localHostname(hostname string) bool {
	return hostname == "127.0.0.1" || hostname == "localhost" || hostname == "::1"
}

func newGitHubClient(client *http.Client, apiURL *url.URL, token []byte) (*github.Client, error) {
	options := []github.ClientOptionsFunc{github.WithHTTPClient(client), github.WithURLs(ptr(apiURL.String()), ptr(apiURL.String()))}
	if len(token) > 0 {
		options = append(options, github.WithAuthToken(string(token)))
	}
	return github.NewClient(options...)
}

func ptr[T any](value T) *T { return &value }

func clonePermissions(value map[string]string) map[string]string {
	if value == nil {
		return nil
	}
	result := make(map[string]string, len(value))
	for key, level := range value {
		result[key] = level
	}
	return result
}

type versionTransport struct{ base http.RoundTripper }

func (t versionTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	clone.Header.Set("X-GitHub-Api-Version", APIVersion)
	return t.base.RoundTrip(clone)
}

type basicAuthTransport struct {
	base     http.RoundTripper
	username string
	password []byte
}

func (t basicAuthTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	clone.SetBasicAuth(t.username, string(t.password))
	clone.Header.Set("X-GitHub-Api-Version", APIVersion)
	return t.base.RoundTrip(clone)
}

func transport(client *http.Client) http.RoundTripper {
	if client != nil && client.Transport != nil {
		return client.Transport
	}
	return http.DefaultTransport
}

func cloneHTTPClient(client *http.Client, roundTripper http.RoundTripper) *http.Client {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	clone := *client
	clone.Transport = roundTripper
	return &clone
}
