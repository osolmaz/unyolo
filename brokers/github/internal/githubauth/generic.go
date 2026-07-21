package githubauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/brokers/github/internal/graphqlmanifest"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opbinding"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/targetregistry"
	"github.com/osolmaz/brokerkit/internal/strictjson"
)

type ExecutionResult struct {
	StatusCode int
	Body       json.RawMessage
}

// UserIdentity is the immutable public identity represented by a selected
// GitHub user credential.
type UserIdentity struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
}

// AuthenticatedUser resolves the account represented by a selected credential
// without exposing the credential itself.
func (m *Manager) AuthenticatedUser(ctx context.Context, selector Metadata) (UserIdentity, error) {
	if m == nil {
		return UserIdentity{}, errors.New("GitHub credential provider is unavailable")
	}
	requestURL := m.relativeAPIURL(m.apiURL, "user", "user", nil)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, http.NoBody)
	if err != nil {
		return UserIdentity{}, errors.New("create GitHub authenticated-user request")
	}
	response, err := m.doAPI(ctx, selector, request)
	if err != nil {
		return UserIdentity{}, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := limitedBody(response.Body, 64<<10)
	if err != nil {
		return UserIdentity{}, err
	}
	return decodeUserIdentity(body)
}

func decodeUserIdentity(body []byte) (UserIdentity, error) {
	var identity UserIdentity
	if strictjson.Decode(body, &identity, false) != nil || identity.ID <= 0 || strings.TrimSpace(identity.Login) == "" {
		return UserIdentity{}, errors.New("GitHub authenticated-user response is invalid")
	}
	return identity, nil
}

// ValidateAuthenticatedUserTarget binds implicit /user endpoints to the
// identity represented by the selected credential.
func (m *Manager) ValidateAuthenticatedUserTarget(ctx context.Context, selector Metadata, target map[string]any) error {
	if targetregistry.String(target, "kind") != "user" {
		return errors.New("GitHub authenticated-user target is invalid")
	}
	identity, err := m.AuthenticatedUser(ctx, selector)
	if err != nil {
		return err
	}
	if !authenticatedUserMatches(target, identity.ID, identity.Login) {
		return errors.New("GitHub authenticated-user target does not match the selected credential")
	}
	return nil
}

func authenticatedUserMatches(target map[string]any, id int64, login string) bool {
	name := targetregistry.String(target, "name")
	if id <= 0 || name == "" || !strings.EqualFold(name, login) {
		return false
	}
	targetID := int64Field(target, "id")
	return targetID == 0 || targetID == id
}

func (m *Manager) SelectMetadata(ctx context.Context, descriptor opcatalog.Descriptor, target map[string]any, userID int64) (Metadata, error) {
	if m == nil {
		return Metadata{}, errors.New("GitHub credential provider is unavailable")
	}
	if m.development != nil {
		return m.development.Metadata(), nil
	}
	switch descriptor.CredentialKind {
	case string(KindAppJWT):
		return m.selectAppMetadata()
	case string(KindInstallation):
		return m.selectInstallationMetadata(ctx, descriptor, target)
	case string(KindUser):
		return m.selectUserMetadata(ctx, target, userID)
	case string(KindDevelopmentToken):
		return m.selectDevelopmentMetadata()
	default:
		return Metadata{}, fmt.Errorf("GitHub credential kind %q is unsupported", descriptor.CredentialKind)
	}
}

func (m *Manager) selectAppMetadata() (Metadata, error) {
	if m.app == nil {
		return Metadata{}, errors.New("GitHub App credential is unavailable")
	}
	return Metadata{Kind: KindAppJWT, APIHost: m.apiURL.Host}, nil
}

func (m *Manager) selectInstallationMetadata(ctx context.Context, descriptor opcatalog.Descriptor, target map[string]any) (Metadata, error) {
	if owner, repo, ok := targetregistry.RepositoryIdentity(target); ok {
		return m.ResolveRepository(ctx, descriptor.Name, owner, repo)
	}
	installationID, err := m.selectedInstallationID(ctx, target)
	if err != nil {
		return Metadata{}, err
	}
	return Metadata{
		Kind:                  KindInstallation,
		InstallationID:        installationID,
		RepositoryIDs:         repositoryIDs(target),
		Permissions:           clonePermissions(descriptor.RequiredGitHubPermissions),
		AllowEmptyPermissions: descriptor.AllowEmptyInstallationPermissions,
		APIHost:               m.apiURL.Host,
	}, nil
}

func (m *Manager) selectedInstallationID(ctx context.Context, target map[string]any) (int64, error) {
	if installationID := installationTargetID(target); installationID > 0 {
		return installationID, nil
	}
	account := installationAccount(target)
	if account == "" {
		return 0, errors.New("GitHub installation selector is incomplete")
	}
	metadata, err := m.InstallationForAccount(ctx, account)
	if err != nil {
		return 0, err
	}
	return metadata.InstallationID, nil
}

func (m *Manager) selectUserMetadata(ctx context.Context, target map[string]any, userID int64) (Metadata, error) {
	userID = selectedUserID(target, userID)
	if userID <= 0 {
		return Metadata{}, errors.New("GitHub user selector is incomplete")
	}
	credential, err := m.UserCredential(ctx, userID)
	if err != nil {
		return Metadata{}, err
	}
	return credential.Metadata(), nil
}

func selectedUserID(target map[string]any, userID int64) int64 {
	if userID > 0 {
		return userID
	}
	if targetID := int64Field(target, "user_id"); targetID > 0 {
		return targetID
	}
	if strings.EqualFold(targetregistry.String(target, "kind"), "user") {
		return int64Field(target, "id")
	}
	return 0
}

func (m *Manager) selectDevelopmentMetadata() (Metadata, error) {
	if m.development == nil {
		return Metadata{}, errors.New("GitHub development credential is unavailable")
	}
	return m.development.Metadata(), nil
}

func installationAccount(target map[string]any) string {
	if account := targetregistry.String(target, "installation_account"); account != "" {
		return account
	}
	switch targetregistry.String(target, "kind") {
	case "organization", "installation", "user":
		return targetregistry.String(target, "name")
	default:
		return ""
	}
}

func (m *Manager) ExecuteREST(ctx context.Context, selector Metadata, binding opbinding.Binding, target, arguments map[string]any) (ExecutionResult, error) {
	for attempt := 0; ; attempt++ {
		response, err := m.executeREST(ctx, selector, binding, target, arguments)
		if err != nil {
			return ExecutionResult{}, err
		}
		if response.StatusCode != http.StatusAccepted || !safeRESTMethod(binding.Method) {
			return decodeRESTResponse(response, binding)
		}
		_ = response.Body.Close()
		if attempt >= 5 {
			return ExecutionResult{}, APIError{Code: "accepted", StatusCode: http.StatusAccepted}
		}
		if err := waitForAcceptedRead(ctx, attempt); err != nil {
			return ExecutionResult{}, err
		}
	}
}

func safeRESTMethod(method string) bool { return method == http.MethodGet || method == http.MethodHead }

func waitForAcceptedRead(ctx context.Context, attempt int) error {
	delay := 100 * time.Millisecond * time.Duration(1<<attempt)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return APIError{Code: "unavailable"}
	case <-timer.C:
		return nil
	}
}

// ExecuteRESTRaw returns one bounded upstream JSON result before projection.
// It is reserved for adapters that immediately move a credential field into
// an encrypted broker-owned slot.
func (m *Manager) ExecuteRESTRaw(ctx context.Context, selector Metadata, binding opbinding.Binding, target, arguments map[string]any) (ExecutionResult, error) {
	response, err := m.executeREST(ctx, selector, binding, target, arguments)
	if err != nil {
		return ExecutionResult{}, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := limitedBody(response.Body, binding.ResponseBytesLimit)
	if err != nil {
		return ExecutionResult{}, err
	}
	var value any
	if strictjson.Decode(body, &value, false) != nil {
		return ExecutionResult{}, errors.New("GitHub API response is invalid")
	}
	return ExecutionResult{StatusCode: response.StatusCode, Body: body}, nil
}

func (m *Manager) executeREST(ctx context.Context, selector Metadata, binding opbinding.Binding, target, arguments map[string]any) (*http.Response, error) {
	if m == nil {
		return nil, errors.New("GitHub credential provider is unavailable")
	}
	request, err := m.newRESTRequest(ctx, binding, target, arguments)
	if err != nil {
		return nil, err
	}
	return m.doAPI(ctx, selector, request)
}

func (m *Manager) newRESTRequest(ctx context.Context, binding opbinding.Binding, target, arguments map[string]any) (*http.Request, error) {
	requestURL, body, err := m.restRequestURLAndBody(binding, target, arguments)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, binding.Method, requestURL, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("create GitHub API request")
	}
	request.Header.Set("Accept", binding.MediaType)
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	return request, nil
}

func (m *Manager) restRequestURLAndBody(binding opbinding.Binding, target, arguments map[string]any) (string, []byte, error) {
	path, query, err := restPathAndQuery(binding, target, arguments)
	if err != nil {
		return "", nil, err
	}
	body, err := restRequestBody(arguments, binding.RequestBytesLimit)
	if err != nil {
		return "", nil, err
	}
	unescapedPath, err := url.PathUnescape(path)
	if err != nil {
		return "", nil, errors.New("GitHub API path is invalid")
	}
	requestURL, err := m.bindingURL(binding, unescapedPath, path, query)
	return requestURL, body, err
}

func restPathAndQuery(binding opbinding.Binding, target, arguments map[string]any) (string, url.Values, error) {
	path, err := restPath(binding, target, arguments)
	if err != nil {
		return "", nil, err
	}
	query, err := restQuery(binding, arguments)
	return path, query, err
}

func restRequestBody(arguments map[string]any, limit int64) ([]byte, error) {
	input, ok := arguments["input"]
	if !ok {
		return nil, nil
	}
	body, err := json.Marshal(input)
	if err != nil {
		return nil, errors.New("encode GitHub request body")
	}
	if int64(len(body)) > limit {
		return nil, errors.New("GitHub request body exceeds its size limit")
	}
	return body, nil
}

func (m *Manager) ExecuteGraphQL(ctx context.Context, selector Metadata, document graphqlmanifest.Document, variables map[string]any) (ExecutionResult, error) {
	if m == nil {
		return ExecutionResult{}, errors.New("GitHub credential provider is unavailable")
	}
	payload := map[string]any{
		"query":         document.Document,
		"operationName": document.OperationName,
		"variables":     variables,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return ExecutionResult{}, errors.New("encode GitHub GraphQL request")
	}
	requestURL, err := m.restURL("/graphql", nil)
	if err != nil {
		return ExecutionResult{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(body))
	if err != nil {
		return ExecutionResult{}, errors.New("create GitHub GraphQL request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	//nolint:bodyclose // decodeGraphQLResponse consumes and closes the returned body on every path.
	response, err := m.doAPI(ctx, selector, request)
	if err != nil {
		return ExecutionResult{}, err
	}
	return decodeGraphQLResponse(response, document)
}

func (m *Manager) ExecuteRESTUpload(ctx context.Context, selector Metadata, binding opbinding.Binding, target, arguments map[string]any,
	source io.Reader, size int64, mediaType string) (ExecutionResult, error) {
	request, err := m.newRESTUploadRequest(ctx, binding, target, arguments, source, size, mediaType)
	if err != nil {
		return ExecutionResult{}, err
	}
	//nolint:bodyclose // decodeRESTResponse consumes and closes the returned body on every path.
	response, err := m.doAPIStream(ctx, selector, request)
	if err != nil {
		return ExecutionResult{}, err
	}
	return decodeRESTResponse(response, binding)
}

func (m *Manager) newRESTUploadRequest(ctx context.Context, binding opbinding.Binding, target, arguments map[string]any, source io.Reader, size int64, mediaType string) (*http.Request, error) {
	if err := validateRESTUpload(m, binding, source, size, mediaType); err != nil {
		return nil, err
	}
	path, err := restPath(binding, target, arguments)
	if err != nil {
		return nil, err
	}
	query, err := restQuery(binding, arguments)
	if err != nil {
		return nil, err
	}
	requestURL, err := m.bindingRESTURL(binding, path, query)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, binding.Method, requestURL, source)
	if err != nil {
		return nil, errors.New("create GitHub stream upload request")
	}
	request.ContentLength = size
	request.Header.Set("Accept", binding.MediaType)
	request.Header.Set("Content-Type", mediaType)
	return request, nil
}

func validateRESTUpload(m *Manager, binding opbinding.Binding, source io.Reader, size int64, mediaType string) error {
	if m == nil || source == nil || size <= 0 || size > binding.RequestBytesLimit || strings.TrimSpace(mediaType) == "" {
		return errors.New("GitHub stream upload is invalid")
	}
	return nil
}

func (m *Manager) ExecuteRESTDownload(ctx context.Context, selector Metadata, binding opbinding.Binding, target, arguments map[string]any) (*http.Response, error) {
	request, err := m.newRESTDownloadRequest(ctx, binding, target, arguments)
	if err != nil {
		return nil, err
	}
	response, err := m.doAPIStreamRequest(ctx, selector, request)
	if err != nil {
		return nil, err
	}
	return m.followDownloadRedirects(ctx, request.URL, response)
}

func (m *Manager) newRESTDownloadRequest(ctx context.Context, binding opbinding.Binding, target, arguments map[string]any) (*http.Request, error) {
	if m == nil || binding.StreamDirection != "download" {
		return nil, errors.New("GitHub stream download is invalid")
	}
	path, query, err := restPathAndQuery(binding, target, arguments)
	if err != nil {
		return nil, err
	}
	requestURL, err := m.bindingRESTURL(binding, path, query)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, binding.Method, requestURL, http.NoBody)
	if err != nil {
		return nil, errors.New("create GitHub stream download request")
	}
	request.Header.Set("Accept", "application/octet-stream")
	return request, nil
}

func (m *Manager) doAPIRequest(ctx context.Context, selector Metadata, request *http.Request) (*http.Response, error) {
	return m.doAPIRequestWithTimeout(ctx, selector, request, 0)
}

func (m *Manager) doAPIStreamRequest(ctx context.Context, selector Metadata, request *http.Request) (*http.Response, error) {
	return m.doAPIRequestWithTimeout(ctx, selector, request, m.streamTimeout)
}

func (m *Manager) doAPIRequestWithTimeout(ctx context.Context, selector Metadata, request *http.Request, timeout time.Duration) (*http.Response, error) {
	client, credential, err := m.requestClient(ctx, selector, timeout)
	if err != nil {
		return nil, err
	}
	if credential != nil {
		accept := request.Header.Get("Accept")
		if err := credential.AuthorizeAPI(request); err != nil {
			return nil, err
		}
		if accept != "" {
			request.Header.Set("Accept", accept)
		}
	}
	request.Header.Set("X-GitHub-Api-Version", APIVersion)
	response, err := client.Do(request)
	if err != nil {
		return nil, APIError{Code: "unavailable"}
	}
	return response, nil
}

func (m *Manager) followDownloadRedirects(ctx context.Context, origin *url.URL, response *http.Response) (*http.Response, error) {
	for redirects := 0; response.StatusCode >= 300 && response.StatusCode < 400; redirects++ {
		location, err := nextDownloadLocation(origin, response, redirects)
		if err != nil {
			return nil, err
		}
		response, err = m.followDownloadRedirect(ctx, location, response.StatusCode)
		if err != nil {
			return nil, err
		}
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		defer func() { _ = response.Body.Close() }()
		return nil, classifyHTTPError(response)
	}
	return response, nil
}

func nextDownloadLocation(origin *url.URL, response *http.Response, redirects int) (*url.URL, error) {
	status := response.StatusCode
	if redirects >= 3 {
		_ = response.Body.Close()
		return nil, APIError{Code: "redirect_not_allowed", StatusCode: status}
	}
	location, err := response.Location()
	_ = response.Body.Close()
	if err != nil || !allowedDownloadURL(origin, location) {
		return nil, APIError{Code: "redirect_not_allowed", StatusCode: status}
	}
	return location, nil
}

func (m *Manager) followDownloadRedirect(ctx context.Context, location *url.URL, status int) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, location.String(), http.NoBody)
	if err != nil {
		return nil, APIError{Code: "redirect_not_allowed", StatusCode: status}
	}
	response, err := m.streamClient().Do(request)
	if err != nil {
		return nil, APIError{Code: "unavailable"}
	}
	return response, nil
}

func allowedDownloadURL(origin, target *url.URL) bool {
	return validRedirectTarget(target) && allowedRedirectScheme(origin, target) && allowedRedirectHost(origin, target)
}

func validRedirectTarget(target *url.URL) bool {
	return target != nil && target.User == nil && target.Hostname() != ""
}

func allowedRedirectScheme(origin, target *url.URL) bool {
	return target.Scheme == "https" || target.Scheme == origin.Scheme && strings.EqualFold(target.Host, origin.Host)
}

func allowedRedirectHost(origin, target *url.URL) bool {
	host := strings.ToLower(target.Hostname())
	return strings.EqualFold(target.Host, origin.Host) || strings.HasSuffix(host, ".githubusercontent.com") ||
		strings.HasSuffix(host, ".github.com") || strings.HasSuffix(host, ".blob.core.windows.net")
}

func (m *Manager) doAPI(ctx context.Context, selector Metadata, request *http.Request) (*http.Response, error) {
	return m.doAPIWithTimeout(ctx, selector, request, 0)
}

func (m *Manager) doAPIStream(ctx context.Context, selector Metadata, request *http.Request) (*http.Response, error) {
	return m.doAPIWithTimeout(ctx, selector, request, m.streamTimeout)
}

func (m *Manager) doAPIWithTimeout(ctx context.Context, selector Metadata, request *http.Request, timeout time.Duration) (*http.Response, error) {
	client, credential, err := m.requestClient(ctx, selector, timeout)
	if err != nil {
		return nil, err
	}
	if credential != nil {
		if err := credential.AuthorizeAPI(request); err != nil {
			return nil, err
		}
	}
	request.Header.Set("X-GitHub-Api-Version", APIVersion)
	response, err := client.Do(request)
	if err != nil {
		return nil, APIError{Code: "unavailable"}
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		defer func() { _ = response.Body.Close() }()
		return nil, classifyHTTPError(response)
	}
	return response, nil
}

func (m *Manager) requestClient(ctx context.Context, selector Metadata, timeout time.Duration) (*http.Client, *Credential, error) {
	client, credential, err := m.clientForMetadata(ctx, selector)
	if err != nil || timeout <= 0 {
		return client, credential, err
	}
	clone := *client
	clone.Timeout = timeout
	return &clone, credential, nil
}

func (m *Manager) streamClient() *http.Client {
	clone := *m.client
	clone.Timeout = m.streamTimeout
	return &clone
}

func (m *Manager) clientForMetadata(ctx context.Context, selector Metadata) (*http.Client, *Credential, error) {
	if !m.matchesAPIHost(selector.APIHost) {
		return nil, nil, errors.New("GitHub credential API host does not match the immutable plan")
	}
	switch selector.Kind {
	case KindAppJWT:
		return m.appClient()
	case KindInstallation:
		credential, err := m.installationCredential(ctx, selector.InstallationID, selector.RepositoryIDs, selector.Permissions, selector.AllowEmptyPermissions)
		return m.client, credential, err
	case KindUser:
		credential, err := m.UserCredential(ctx, selector.UserID)
		return m.client, credential, err
	case KindDevelopmentToken:
		return m.developmentClient()
	default:
		return nil, nil, errors.New("GitHub credential selector is invalid")
	}
}

func (m *Manager) matchesAPIHost(host string) bool {
	return m != nil && m.apiURL != nil && strings.EqualFold(strings.TrimSpace(host), m.apiURL.Host)
}

func (m *Manager) appClient() (*http.Client, *Credential, error) {
	if m.app == nil || m.app.round == nil {
		return nil, nil, errors.New("GitHub App credential is unavailable")
	}
	return cloneHTTPClient(m.client, versionTransport{base: m.app.round}), nil, nil
}

func (m *Manager) developmentClient() (*http.Client, *Credential, error) {
	if m.development == nil {
		return nil, nil, errors.New("GitHub development credential is unavailable")
	}
	return m.client, m.development, nil
}

func decodeRESTResponse(response *http.Response, binding opbinding.Binding) (ExecutionResult, error) {
	defer func() { _ = response.Body.Close() }()
	body, err := limitedBody(response.Body, binding.ResponseBytesLimit)
	if err != nil {
		return ExecutionResult{}, err
	}
	if response.StatusCode == http.StatusNoContent || len(bytes.TrimSpace(body)) == 0 {
		return ExecutionResult{StatusCode: response.StatusCode, Body: emptyRESTResult(binding.ResponseRootType)}, nil
	}
	var value any
	if err := strictjson.Decode(body, &value, false); err != nil {
		return ExecutionResult{}, errors.New("GitHub API response is invalid")
	}
	projected, ok := projectRESTResponse(value, binding.ResponseProjection)
	if !ok {
		projected = emptyProjection(value)
	}
	encoded, err := json.Marshal(projected)
	if err != nil {
		return ExecutionResult{}, errors.New("encode projected GitHub response")
	}
	return ExecutionResult{StatusCode: response.StatusCode, Body: encoded}, nil
}

func emptyRESTResult(rootType string) json.RawMessage {
	if rootType == "array" {
		return json.RawMessage(`[]`)
	}
	return json.RawMessage(`{}`)
}

func emptyProjection(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return map[string]any{}
	case []any:
		result := make([]any, len(typed))
		for index, child := range typed {
			result[index] = emptyProjection(child)
		}
		return result
	default:
		return value
	}
}

func projectRESTResponse(value any, projection []string) (any, bool) {
	if len(projection) == 0 {
		return value, true
	}
	allowed := make(map[string]bool, len(projection))
	for _, path := range projection {
		allowed[path] = true
	}
	return projectByPath(value, allowed, "")
}

func decodeGraphQLResponse(response *http.Response, document graphqlmanifest.Document) (ExecutionResult, error) {
	defer func() { _ = response.Body.Close() }()
	body, err := limitedBody(response.Body, 4<<20)
	if err != nil {
		return ExecutionResult{}, err
	}
	var payload struct {
		Data   map[string]any `json:"data"`
		Errors []struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"errors"`
	}
	if err := strictjson.Decode(body, &payload, false); err != nil {
		return ExecutionResult{}, errors.New("GitHub GraphQL response is invalid")
	}
	if len(payload.Errors) > 0 {
		return ExecutionResult{}, APIError{Code: safeGitHubCode(payload.Errors[0].Type, "graphql_error"), StatusCode: response.StatusCode,
			Message: safeGitHubMessage(payload.Errors[0].Message), RequestID: githubRequestID(response.Header)}
	}
	projected, ok := projectJSON(payload.Data, document.ResponseProjection)
	if !ok {
		return ExecutionResult{}, errors.New("GitHub GraphQL response omitted the projected data")
	}
	encoded, err := json.Marshal(projected)
	if err != nil {
		return ExecutionResult{}, errors.New("encode projected GitHub GraphQL response")
	}
	return ExecutionResult{StatusCode: response.StatusCode, Body: encoded}, nil
}

func limitedBody(body io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("GitHub response body limit is invalid")
	}
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, APIError{Code: "unavailable"}
	}
	if int64(len(data)) > limit {
		return nil, errors.New("GitHub response body exceeds its size limit")
	}
	return data, nil
}

func restPath(binding opbinding.Binding, target, arguments map[string]any) (string, error) {
	parts := make([]string, 0, len(binding.PathParameters)*2)
	for _, name := range binding.PathParameters {
		field, targetOwned := targetFieldForPath(name, binding.TargetPathParameters)
		var value string
		var err error
		if targetOwned {
			value, err = targetPathValue(name, field, target)
		} else {
			value, err = argumentPathValue(name, arguments)
		}
		if err != nil {
			return "", err
		}
		parts = append(parts, "{"+name+"}", escapePathParameter(value))
	}
	replacer := strings.NewReplacer(parts...)
	return replacer.Replace(binding.PathTemplate), nil
}

func argumentPathValue(name string, arguments map[string]any) (string, error) {
	value, found := arguments[name]
	if !found {
		return "", fmt.Errorf("GitHub target path parameter %q is unavailable", name)
	}
	switch typed := value.(type) {
	case string:
		if strings.TrimSpace(typed) != "" {
			return typed, nil
		}
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10), nil
		}
	case json.Number:
		return typed.String(), nil
	}
	return "", fmt.Errorf("GitHub target path parameter %q is invalid", name)
}

func restQuery(binding opbinding.Binding, arguments map[string]any) (url.Values, error) {
	values := url.Values{}
	for _, parameter := range binding.ArgumentParameters {
		if parameter.In != "query" {
			continue
		}
		value, found := arguments[parameter.Name]
		if !found {
			continue
		}
		if err := addQueryValue(values, parameter.Name, value); err != nil {
			return nil, fmt.Errorf("GitHub query parameter %q is invalid", parameter.Name)
		}
	}
	return values, nil
}

func addQueryValue(values url.Values, name string, value any) error {
	if typed, ok := value.([]any); ok {
		for _, item := range typed {
			if err := addQueryValue(values, name, item); err != nil {
				return err
			}
		}
		return nil
	}
	encoded, include, err := scalarQueryValue(value)
	if err != nil {
		return err
	}
	if include {
		values.Add(name, encoded)
	}
	return nil
}

func scalarQueryValue(value any) (string, bool, error) {
	switch typed := value.(type) {
	case string:
		return typed, true, nil
	case float64, json.Number:
		encoded, err := formatQueryNumber(typed)
		return encoded, true, err
	case bool:
		return strconv.FormatBool(typed), true, nil
	case nil:
		return "", false, nil
	default:
		return "", false, errors.New("unsupported query value")
	}
}

func formatQueryNumber(value any) (string, error) {
	switch typed := value.(type) {
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64), nil
	case json.Number:
		if _, err := typed.Float64(); err == nil {
			return typed.String(), nil
		}
	}
	return "", errors.New("invalid numeric query value")
}

func targetPathValue(name, field string, target map[string]any) (string, error) {
	if field == "id" || field == "number" {
		if value := int64Field(target, field); value > 0 {
			return strconv.FormatInt(value, 10), nil
		}
	} else if value := targetregistry.String(target, field); value != "" {
		return value, nil
	}
	return "", fmt.Errorf("GitHub target is missing path parameter %q", name)
}

func targetFieldForPath(name string, parameters []opbinding.TargetParameter) (string, bool) {
	for _, parameter := range parameters {
		if parameter.Name == name {
			return parameter.Field, true
		}
	}
	return "", false
}

func repositoryIDs(target map[string]any) []int64 {
	raw, found := target["repository_ids"]
	if !found {
		return nil
	}
	items, ok := raw.([]any)
	if !ok {
		return nil
	}
	result := make([]int64, 0, len(items))
	for _, item := range items {
		if value, ok := integerValue(item); ok && value > 0 {
			result = append(result, value)
		}
	}
	return canonicalRepositoryIDs(result)
}

func int64Field(values map[string]any, key string) int64 {
	value, found := values[key]
	if !found {
		return 0
	}
	number, _ := integerValue(value)
	return number
}

func integerValue(value any) (int64, bool) {
	switch typed := value.(type) {
	case float64:
		return int64(typed), typed == float64(int64(typed))
	case int64:
		return typed, true
	case json.Number:
		number, err := typed.Int64()
		return number, err == nil
	default:
		return 0, false
	}
}
