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

// ValidateAuthenticatedUserTarget binds implicit /user endpoints to the
// identity represented by the selected credential.
func (m *Manager) ValidateAuthenticatedUserTarget(ctx context.Context, selector Metadata, target map[string]any) error {
	if targetregistry.String(target, "kind") != "user" {
		return errors.New("GitHub authenticated-user target is invalid")
	}
	requestURL := m.apiURL.ResolveReference(&url.URL{Path: "/user"})
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), http.NoBody)
	if err != nil {
		return errors.New("create GitHub authenticated-user request")
	}
	response, err := m.doAPI(ctx, selector, request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := limitedBody(response.Body, 64<<10)
	if err != nil {
		return err
	}
	var identity struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	}
	if strictjson.Decode(body, &identity, false) != nil || !authenticatedUserMatches(target, identity.ID, identity.Login) {
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

//nolint:cyclop // Credential-domain selection remains explicit at the provider trust boundary.
func (m *Manager) SelectMetadata(ctx context.Context, descriptor opcatalog.Descriptor, target map[string]any, userID int64) (Metadata, error) {
	if m == nil {
		return Metadata{}, errors.New("GitHub credential provider is unavailable")
	}
	if m.development != nil {
		return m.development.Metadata(), nil
	}
	switch descriptor.CredentialKind {
	case string(KindAppJWT):
		if m.app == nil {
			return Metadata{}, errors.New("GitHub App credential is unavailable")
		}
		return Metadata{Kind: KindAppJWT, APIHost: m.apiURL.Host}, nil
	case string(KindInstallation):
		if owner, repo, ok := targetregistry.RepositoryIdentity(target); ok {
			return m.ResolveRepository(ctx, descriptor.Name, owner, repo)
		}
		installationID := int64Field(target, "installation_id")
		if installationID <= 0 {
			account := targetregistry.String(target, "owner")
			if account == "" {
				account = targetregistry.String(target, "name")
			}
			if account != "" {
				metadata, err := m.InstallationForAccount(ctx, account)
				if err == nil {
					installationID = metadata.InstallationID
				}
			}
		}
		if installationID <= 0 {
			installationID = int64Field(target, "id")
		}
		if installationID <= 0 {
			return Metadata{}, errors.New("GitHub installation selector is incomplete")
		}
		return Metadata{
			Kind:           KindInstallation,
			InstallationID: installationID,
			RepositoryIDs:  repositoryIDs(target),
			Permissions:    clonePermissions(descriptor.RequiredGitHubPermissions),
			APIHost:        m.apiURL.Host,
		}, nil
	case string(KindUser):
		if userID <= 0 {
			userID = int64Field(target, "user_id")
		}
		if userID <= 0 && strings.EqualFold(targetregistry.String(target, "kind"), "user") {
			userID = int64Field(target, "id")
		}
		if userID <= 0 {
			return Metadata{}, errors.New("GitHub user selector is incomplete")
		}
		credential, err := m.UserCredential(ctx, userID)
		if err != nil {
			return Metadata{}, err
		}
		return credential.Metadata(), nil
	case string(KindDevelopmentToken):
		if m.development == nil {
			return Metadata{}, errors.New("GitHub development credential is unavailable")
		}
		return m.development.Metadata(), nil
	default:
		return Metadata{}, fmt.Errorf("GitHub credential kind %q is unsupported", descriptor.CredentialKind)
	}
}

func (m *Manager) ExecuteREST(ctx context.Context, selector Metadata, binding opbinding.Binding, target, arguments map[string]any) (ExecutionResult, error) {
	//nolint:bodyclose // decodeRESTResponse consumes and closes the returned body on every path.
	response, err := m.executeREST(ctx, selector, binding, target, arguments)
	if err != nil {
		return ExecutionResult{}, err
	}
	return decodeRESTResponse(response, binding)
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

//nolint:cyclop // Request projection and bounds remain visible in one audited transport path.
func (m *Manager) executeREST(ctx context.Context, selector Metadata, binding opbinding.Binding, target, arguments map[string]any) (*http.Response, error) {
	if m == nil {
		return nil, errors.New("GitHub credential provider is unavailable")
	}
	path, err := restPath(binding, target, arguments)
	if err != nil {
		return nil, err
	}
	query, err := restQuery(binding, arguments)
	if err != nil {
		return nil, err
	}
	var body []byte
	if input, ok := arguments["input"]; ok {
		body, err = json.Marshal(input)
		if err != nil {
			return nil, errors.New("encode GitHub request body")
		}
		if int64(len(body)) > binding.RequestBytesLimit {
			return nil, errors.New("GitHub request body exceeds its size limit")
		}
	}
	unescapedPath, err := url.PathUnescape(path)
	if err != nil {
		return nil, errors.New("GitHub API path is invalid")
	}
	requestURL := m.apiURL.ResolveReference(&url.URL{Path: unescapedPath, RawPath: path, RawQuery: query.Encode()})
	request, err := http.NewRequestWithContext(ctx, binding.Method, requestURL.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("create GitHub API request")
	}
	request.Header.Set("Accept", binding.MediaType)
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := m.doAPI(ctx, selector, request)
	if err != nil {
		return nil, err
	}
	return response, nil
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
	requestURL := m.apiURL.ResolveReference(&url.URL{Path: "/graphql"})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader(body))
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

//nolint:cyclop // Upload bounds and immutable binding projection remain explicit at the stream boundary.
func (m *Manager) ExecuteRESTUpload(ctx context.Context, selector Metadata, binding opbinding.Binding, target, arguments map[string]any,
	source io.Reader, size int64, mediaType string) (ExecutionResult, error) {
	if m == nil || source == nil || size <= 0 || size > binding.RequestBytesLimit || strings.TrimSpace(mediaType) == "" {
		return ExecutionResult{}, errors.New("GitHub stream upload is invalid")
	}
	path, err := restPath(binding, target, arguments)
	if err != nil {
		return ExecutionResult{}, err
	}
	query, err := restQuery(binding, arguments)
	if err != nil {
		return ExecutionResult{}, err
	}
	requestURL, err := m.restURL(path, query)
	if err != nil {
		return ExecutionResult{}, err
	}
	request, err := http.NewRequestWithContext(ctx, binding.Method, requestURL, source)
	if err != nil {
		return ExecutionResult{}, errors.New("create GitHub stream upload request")
	}
	request.ContentLength = size
	request.Header.Set("Accept", binding.MediaType)
	request.Header.Set("Content-Type", mediaType)
	//nolint:bodyclose // decodeRESTResponse consumes and closes the returned body on every path.
	response, err := m.doAPI(ctx, selector, request)
	if err != nil {
		return ExecutionResult{}, err
	}
	return decodeRESTResponse(response, binding)
}

func (m *Manager) ExecuteRESTDownload(ctx context.Context, selector Metadata, binding opbinding.Binding, target, arguments map[string]any) (*http.Response, error) {
	if m == nil || binding.StreamDirection != "download" {
		return nil, errors.New("GitHub stream download is invalid")
	}
	path, err := restPath(binding, target, arguments)
	if err != nil {
		return nil, err
	}
	query, err := restQuery(binding, arguments)
	if err != nil {
		return nil, err
	}
	requestURL, err := m.restURL(path, query)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, binding.Method, requestURL, http.NoBody)
	if err != nil {
		return nil, errors.New("create GitHub stream download request")
	}
	request.Header.Set("Accept", "application/octet-stream")
	response, err := m.doAPIRequest(ctx, selector, request)
	if err != nil {
		return nil, err
	}
	return m.followDownloadRedirects(ctx, request.URL, response)
}

func (m *Manager) restURL(path string, query url.Values) (string, error) {
	unescapedPath, err := url.PathUnescape(path)
	if err != nil {
		return "", errors.New("GitHub API path is invalid")
	}
	return m.apiURL.ResolveReference(&url.URL{Path: unescapedPath, RawPath: path, RawQuery: query.Encode()}).String(), nil
}

func (m *Manager) doAPIRequest(ctx context.Context, selector Metadata, request *http.Request) (*http.Response, error) {
	client, credential, err := m.clientForMetadata(ctx, selector)
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
		if redirects >= 3 {
			_ = response.Body.Close()
			return nil, APIError{Code: "redirect_not_allowed", StatusCode: response.StatusCode}
		}
		location, err := response.Location()
		_ = response.Body.Close()
		if err != nil || !allowedDownloadURL(origin, location) {
			return nil, APIError{Code: "redirect_not_allowed", StatusCode: response.StatusCode}
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, location.String(), http.NoBody)
		if err != nil {
			return nil, APIError{Code: "redirect_not_allowed", StatusCode: response.StatusCode}
		}
		response, err = m.client.Do(request)
		if err != nil {
			return nil, APIError{Code: "unavailable"}
		}
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		defer func() { _ = response.Body.Close() }()
		return nil, classifyHTTPError(response)
	}
	return response, nil
}

func allowedDownloadURL(origin, target *url.URL) bool {
	if target == nil || target.User != nil || target.Hostname() == "" {
		return false
	}
	if target.Scheme != "https" && (target.Scheme != origin.Scheme || !strings.EqualFold(target.Host, origin.Host)) {
		return false
	}
	host := strings.ToLower(target.Hostname())
	return strings.EqualFold(target.Host, origin.Host) || strings.HasSuffix(host, ".githubusercontent.com") ||
		strings.HasSuffix(host, ".github.com") || strings.HasSuffix(host, ".blob.core.windows.net")
}

func (m *Manager) doAPI(ctx context.Context, selector Metadata, request *http.Request) (*http.Response, error) {
	client, credential, err := m.clientForMetadata(ctx, selector)
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

func (m *Manager) clientForMetadata(ctx context.Context, selector Metadata) (*http.Client, *Credential, error) {
	switch selector.Kind {
	case KindAppJWT:
		if m.app == nil || m.app.round == nil {
			return nil, nil, errors.New("GitHub App credential is unavailable")
		}
		return cloneHTTPClient(m.client, versionTransport{base: m.app.round}), nil, nil
	case KindInstallation:
		credential, err := m.InstallationCredential(ctx, selector.InstallationID, selector.RepositoryIDs, selector.Permissions)
		return m.client, credential, err
	case KindUser:
		credential, err := m.UserCredential(ctx, selector.UserID)
		return m.client, credential, err
	case KindDevelopmentToken:
		if m.development == nil {
			return nil, nil, errors.New("GitHub development credential is unavailable")
		}
		return m.client, m.development, nil
	default:
		return nil, nil, errors.New("GitHub credential selector is invalid")
	}
}

func decodeRESTResponse(response *http.Response, binding opbinding.Binding) (ExecutionResult, error) {
	defer func() { _ = response.Body.Close() }()
	body, err := limitedBody(response.Body, binding.ResponseBytesLimit)
	if err != nil {
		return ExecutionResult{}, err
	}
	if response.StatusCode == http.StatusNoContent || len(bytes.TrimSpace(body)) == 0 {
		return ExecutionResult{StatusCode: response.StatusCode, Body: json.RawMessage(`{}`)}, nil
	}
	var value any
	if err := strictjson.Decode(body, &value, false); err != nil {
		return ExecutionResult{}, errors.New("GitHub API response is invalid")
	}
	projected, ok := projectJSON(value, binding.ResponseProjection)
	if !ok {
		projected = map[string]any{}
	}
	encoded, err := json.Marshal(projected)
	if err != nil {
		return ExecutionResult{}, errors.New("encode projected GitHub response")
	}
	return ExecutionResult{StatusCode: response.StatusCode, Body: encoded}, nil
}

func projectRESTResponse(value any, projection []string) (any, bool) {
	if len(projection) == 0 {
		return value, true
	}
	allowed := make(map[string]bool, len(projection))
	for _, name := range projection {
		allowed[name] = true
	}
	return projectTopLevel(value, allowed)
}

func projectTopLevel(value any, allowed map[string]bool) (any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		result := map[string]any{}
		for key, child := range typed {
			if allowed[key] {
				result[key] = child
			}
		}
		return result, len(result) > 0
	case []any:
		result := make([]any, 0, len(typed))
		for _, child := range typed {
			if projected, keep := projectTopLevel(child, allowed); keep {
				result = append(result, projected)
			}
		}
		return result, len(result) > 0
	default:
		return nil, false
	}
}

func decodeGraphQLResponse(response *http.Response, document graphqlmanifest.Document) (ExecutionResult, error) {
	defer func() { _ = response.Body.Close() }()
	body, err := limitedBody(response.Body, 4<<20)
	if err != nil {
		return ExecutionResult{}, err
	}
	var payload struct {
		Data   map[string]any `json:"data"`
		Errors []map[string]any
	}
	if err := strictjson.Decode(body, &payload, false); err != nil {
		return ExecutionResult{}, errors.New("GitHub GraphQL response is invalid")
	}
	if len(payload.Errors) > 0 {
		return ExecutionResult{}, APIError{Code: "graphql_error", StatusCode: response.StatusCode}
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

func classifyHTTPError(response *http.Response) error {
	status := responseStatus(response)
	if status == http.StatusForbidden && strings.TrimSpace(response.Header.Get("Retry-After")) != "" {
		return APIError{Code: "secondary_rate_limited", StatusCode: status}
	}
	if status == http.StatusTooManyRequests || response.Header.Get("X-RateLimit-Remaining") == "0" {
		return APIError{Code: "rate_limited", StatusCode: status, RateReset: rateReset(response.Header)}
	}
	if status >= http.StatusMultipleChoices && status < http.StatusBadRequest {
		return APIError{Code: "redirect_not_allowed", StatusCode: status}
	}
	return APIError{Code: statusCodeName(status), StatusCode: status}
}

func rateReset(header http.Header) time.Time {
	value := strings.TrimSpace(header.Get("X-RateLimit-Reset"))
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || seconds <= 0 {
		return time.Time{}
	}
	return time.Unix(seconds, 0).UTC()
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
		parts = append(parts, "{"+name+"}", url.PathEscape(value))
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

func projectJSON(value any, projection []string) (any, bool) {
	if len(projection) == 0 {
		return value, true
	}
	nameProjection := true
	allowed := make(map[string]bool, len(projection))
	for _, entry := range projection {
		allowed[entry] = true
		if strings.Contains(entry, ".") {
			nameProjection = false
		}
	}
	if nameProjection {
		return projectByName(value, allowed)
	}
	return projectByPath(value, allowed, "")
}

func projectByName(value any, allowed map[string]bool) (any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		result := map[string]any{}
		for key, child := range typed {
			if allowed[key] {
				result[key] = child
				continue
			}
			if projected, keep := projectByName(child, allowed); keep {
				result[key] = projected
			}
		}
		return result, len(result) > 0
	case []any:
		result := make([]any, 0, len(typed))
		for _, child := range typed {
			if projected, keep := projectByName(child, allowed); keep {
				result = append(result, projected)
			}
		}
		return result, len(result) > 0
	default:
		return nil, false
	}
}

func projectByPath(value any, allowed map[string]bool, prefix string) (any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		result := map[string]any{}
		for key, child := range typed {
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			if allowed[path] {
				result[key] = child
				continue
			}
			if projected, keep := projectByPath(child, allowed, path); keep {
				result[key] = projected
			}
		}
		return result, len(result) > 0
	case []any:
		result := make([]any, 0, len(typed))
		for _, child := range typed {
			if projected, keep := projectByPath(child, allowed, prefix); keep {
				result = append(result, projected)
			}
		}
		return result, len(result) > 0
	default:
		return nil, allowed[prefix]
	}
}
