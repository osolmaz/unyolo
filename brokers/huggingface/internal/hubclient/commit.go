package hubclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const maxCommitOperations = 256

var commitOIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)

func (c *Client) CreateCommit(ctx context.Context, request CommitRequest) (CommitResult, error) {
	if err := validateCommitRequest(request); err != nil {
		return CommitResult{}, err
	}
	body, err := commitNDJSON(request)
	if err != nil {
		return CommitResult{}, err
	}
	query := commitQuery(request)
	var result CommitResult
	path := request.Ref.apiPath("commit", url.PathEscape(request.Revision))
	if err := c.call(ctx, callSpec{method: http.MethodPost, path: path, query: query, rawBody: body, contentType: "application/x-ndjson", out: &result}); err != nil {
		return CommitResult{}, err
	}
	if !validCommitResult(result) {
		return CommitResult{}, &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
	}
	return result, nil
}

func commitQuery(request CommitRequest) url.Values {
	query := make(url.Values)
	if request.CreatePR {
		query.Set("create_pr", "1")
	}
	if request.HotReload {
		query.Set("hot_reload", "1")
	}
	return query
}

func validCommitResult(result CommitResult) bool {
	return commitOIDPattern.MatchString(result.CommitOID) && result.CommitURL != ""
}

func (c *Client) RepoPathsInfo(ctx context.Context, ref RepoRef, revision string, paths []string) ([]RepoPathInfo, error) {
	if err := validateRepoPathsInfoRequest(ref, revision, paths); err != nil {
		return nil, err
	}
	body := struct {
		Paths  []string `json:"paths"`
		Expand bool     `json:"expand"`
	}{Paths: paths, Expand: false}
	var wire []repoPathInfoWire
	if err := c.call(ctx, callSpec{method: http.MethodPost, path: ref.apiPath("paths-info", url.PathEscape(revision)), body: body, out: &wire}); err != nil {
		return nil, err
	}
	return repoPathsInfoFromWire(wire)
}

func validateRepoPathsInfoRequest(ref RepoRef, revision string, paths []string) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	if !ValidGitRefComponent(revision) || len(paths) == 0 || len(paths) > 500 {
		return errors.New("hubclient: repository paths request is invalid")
	}
	for _, path := range paths {
		if !ValidRepoPath(path, false) {
			return errors.New("hubclient: repository path is invalid")
		}
	}
	return nil
}

func repoPathsInfoFromWire(wire []repoPathInfoWire) ([]RepoPathInfo, error) {
	result := make([]RepoPathInfo, 0, len(wire))
	for _, item := range wire {
		info, err := repoPathInfoFromWire(item)
		if err != nil {
			return nil, err
		}
		result = append(result, info)
	}
	return result, nil
}

func repoPathInfoFromWire(item repoPathInfoWire) (RepoPathInfo, error) {
	if !ValidRepoPath(item.Path, item.Type == "directory") || item.OID == "" || item.Size < 0 {
		return RepoPathInfo{}, &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
	}
	return RepoPathInfo{Type: item.Type, Path: item.Path, OID: item.OID, Size: item.Size, LFSSHA: item.LFS.SHA256, XetHash: item.XetHash}, nil
}

func (c *Client) RepoInfoRevision(ctx context.Context, ref RepoRef, revision string) (RepoInfo, error) {
	if err := ref.Validate(); err != nil {
		return RepoInfo{}, err
	}
	if !ValidGitRefComponent(revision) {
		return RepoInfo{}, errors.New("hubclient: repository revision is invalid")
	}
	var wire repoInfoWire
	if err := c.call(ctx, callSpec{method: http.MethodGet, path: ref.apiPath("revision", url.PathEscape(revision)), out: &wire}); err != nil {
		return RepoInfo{}, err
	}
	info := wire.toRepoInfo()
	if info.ID != ref.ID() || info.SHA == "" {
		return RepoInfo{}, &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
	}
	return info, nil
}

func (c *Client) ReadRepoFile(ctx context.Context, ref RepoRef, revision, path string) ([]byte, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	if !ValidGitRefComponent(revision) || !ValidRepoPath(path, false) {
		return nil, errors.New("hubclient: repository file identity is invalid")
	}
	ctx, cancel := c.callContext(ctx)
	defer cancel()
	response, err := c.readRepoFileResponse(ctx, ref, revision, path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	return c.readResponsePayload(response)
}

func (c *Client) readRepoFileResponse(ctx context.Context, ref RepoRef, revision, path string) (*http.Response, error) {
	request, err := c.newRequest(ctx, callSpec{method: http.MethodGet, path: repoFilePath(ref, revision, path)})
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: c.httpClient.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return nil, &Error{Code: CodeUnavailable}
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return c.followRepoFileRedirect(ctx, client, response)
	}
	return response, nil
}

func repoFilePath(ref RepoRef, revision, path string) string {
	prefix := ""
	if ref.Type != RepoTypeModel {
		prefix = "/" + string(ref.Type) + "s"
	}
	return prefix + "/" + url.PathEscape(ref.Owner) + "/" + url.PathEscape(ref.Name) + "/resolve/" + url.PathEscape(revision) + "/" + escapeRepoPath(path)
}

func (c *Client) followRepoFileRedirect(ctx context.Context, client *http.Client, response *http.Response) (*http.Response, error) {
	location, err := c.repoFileRedirectLocation(response)
	if err != nil {
		return nil, &Error{Code: CodeResponseInvalid, StatusCode: response.StatusCode}
	}
	_ = response.Body.Close()
	return doRepoFileRedirect(ctx, client, location)
}

func (c *Client) repoFileRedirectLocation(response *http.Response) (*url.URL, error) {
	location, err := response.Location()
	if err != nil || !c.trustedContentLocation(location) {
		return nil, errors.New("hubclient: content redirect is invalid")
	}
	return location, nil
}

func repoFileRedirectRequest(ctx context.Context, location *url.URL) (*http.Request, error) {
	redirect, err := http.NewRequestWithContext(ctx, http.MethodGet, location.String(), nil)
	if err != nil {
		return nil, errors.New("hubclient: content redirect is invalid")
	}
	redirect.Header.Set("Accept", "application/octet-stream")
	return redirect, nil
}

func doRepoFileRedirect(ctx context.Context, client *http.Client, location *url.URL) (*http.Response, error) {
	redirect, err := repoFileRedirectRequest(ctx, location)
	if err != nil {
		return nil, err
	}
	return repoFileRedirectResponse(client, redirect)
}

func repoFileRedirectResponse(client *http.Client, redirect *http.Request) (*http.Response, error) {
	response, err := client.Do(redirect)
	if err != nil {
		return nil, &Error{Code: CodeUnavailable}
	}
	return response, nil
}

func (c *Client) readResponsePayload(response *http.Response) ([]byte, error) {
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, statusError(response.StatusCode, response.Header)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, c.maxResponseBytes+1))
	if err != nil {
		return nil, &Error{Code: CodeUnavailable, StatusCode: response.StatusCode}
	}
	if int64(len(payload)) > c.maxResponseBytes {
		return nil, &Error{Code: CodeResponseInvalid, StatusCode: response.StatusCode}
	}
	return payload, nil
}

func (c *Client) DuplicateLFSFile(ctx context.Context, source, destination RepoRef, info RepoPathInfo) error {
	if err := validateDuplicateLFSRequest(source, destination, info); err != nil {
		return err
	}
	body := duplicateLFSBody(destination, info)
	var result mutationBatchResult
	if err := c.call(ctx, callSpec{method: http.MethodPost, path: source.apiPath("lfs-files", "duplicate"), body: body, out: &result}); err != nil {
		return err
	}
	if !batchMutationSucceeded(result, 1) {
		return &Error{Code: CodeInvalid, StatusCode: http.StatusOK}
	}
	return nil
}

func validateDuplicateLFSRequest(source, destination RepoRef, info RepoPathInfo) error {
	if err := source.Validate(); err != nil {
		return err
	}
	if err := destination.Validate(); err != nil {
		return err
	}
	if !validLFSInfo(info) {
		return errors.New("hubclient: LFS source metadata is invalid")
	}
	return nil
}

func validLFSInfo(info RepoPathInfo) bool {
	return validXetHash(strings.ToLower(info.XetHash)) &&
		validXetHash(strings.ToLower(info.LFSSHA)) &&
		ValidRepoPath(info.Path, false)
}

func duplicateLFSBody(destination RepoRef, info RepoPathInfo) any {
	body := struct {
		Target struct {
			Type string `json:"type"`
			Name string `json:"name"`
		} `json:"target"`
		Files []struct {
			XetHash  string `json:"xetHash"`
			SHA256   string `json:"sha256"`
			Filename string `json:"filename"`
		} `json:"files"`
	}{}
	body.Target.Type = string(destination.Type)
	body.Target.Name = destination.ID()
	body.Files = append(body.Files, struct {
		XetHash  string `json:"xetHash"`
		SHA256   string `json:"sha256"`
		Filename string `json:"filename"`
	}{XetHash: info.XetHash, SHA256: info.LFSSHA, Filename: info.Path})
	return body
}

func ValidRepoPath(value string, folder bool) bool {
	if invalidRepoPathShape(value) {
		return false
	}
	trimmed := strings.TrimSuffix(value, "/")
	if folder != strings.HasSuffix(value, "/") || trimmed == "" {
		return false
	}
	return repoPathPartsValid(trimmed)
}

func invalidRepoPathShape(value string) bool {
	return value == "" ||
		len(value) > 1000 ||
		strings.HasPrefix(value, "/") ||
		strings.Contains(value, "\\") ||
		strings.ContainsRune(value, 0)
}

func repoPathPartsValid(value string) bool {
	for _, part := range strings.Split(value, "/") {
		if invalidRepoPathPart(part) {
			return false
		}
	}
	return true
}

func invalidRepoPathPart(part string) bool {
	return part == "" || part == "." || part == ".." || part == ".git"
}

func ValidateCommitOperations(operations []CommitOperation) error {
	if len(operations) == 0 || len(operations) > maxCommitOperations {
		return errors.New("hubclient: commit operation count is invalid")
	}
	seen := make(map[string]bool, len(operations))
	for _, operation := range operations {
		folder := operation.Kind == CommitDeletedFolder
		if !ValidRepoPath(operation.Path, folder) || seen[operation.Path] {
			return errors.New("hubclient: commit operation path is invalid or duplicated")
		}
		seen[operation.Path] = true
		if err := validateCommitOperationShape(operation); err != nil {
			return err
		}
	}
	return nil
}

func validateCommitOperationShape(operation CommitOperation) error {
	switch operation.Kind {
	case CommitFile:
		return validateRegularCommitFile(operation)
	case CommitLFSFile:
		return validateLFSCommitFile(operation)
	case CommitDeletedFile, CommitDeletedFolder:
		return validateDeletedCommitPath(operation)
	default:
		return errors.New("hubclient: commit operation type is invalid")
	}
}

func validateRegularCommitFile(operation CommitOperation) error {
	if operation.Content == nil || operation.OID != "" || operation.Size != 0 {
		return errors.New("hubclient: regular file operation is invalid")
	}
	return nil
}

func validateLFSCommitFile(operation CommitOperation) error {
	if operation.Content != nil || !validXetHash(strings.ToLower(operation.OID)) || operation.Size < 0 {
		return errors.New("hubclient: LFS file operation is invalid")
	}
	return nil
}

func validateDeletedCommitPath(operation CommitOperation) error {
	if operation.Content != nil || operation.OID != "" || operation.Size != 0 {
		return errors.New("hubclient: delete operation is invalid")
	}
	return nil
}

func validateCommitRequest(request CommitRequest) error {
	if err := request.Ref.Validate(); err != nil {
		return err
	}
	if !validCommitMetadata(request) {
		return errors.New("hubclient: commit metadata is invalid")
	}
	return ValidateCommitOperations(request.Operations)
}

func validCommitMetadata(request CommitRequest) bool {
	return ValidGitRefComponent(request.Revision) &&
		strings.TrimSpace(request.Summary) != "" &&
		len(request.Summary) <= 500 &&
		len(request.Description) <= 10_000 &&
		validParentCommit(request.ParentCommit) &&
		(!request.HotReload || request.Ref.Type == RepoTypeSpace)
}

func validParentCommit(value string) bool {
	return value == "" || commitOIDPattern.MatchString(value)
}

func commitNDJSON(request CommitRequest) ([]byte, error) {
	header := map[string]any{"summary": request.Summary, "description": request.Description}
	if request.ParentCommit != "" {
		header["parentCommit"] = request.ParentCommit
	}
	lines := []any{map[string]any{"key": "header", "value": header}}
	for _, operation := range request.Operations {
		lines = append(lines, commitNDJSONLine(operation))
	}
	var body bytes.Buffer
	for _, line := range lines {
		encoded, err := json.Marshal(line)
		if err != nil || body.Len()+len(encoded)+1 > maxRequestBodyBytes {
			return nil, errors.New("hubclient: commit body exceeds the bounded request limit")
		}
		body.Write(encoded)
		body.WriteByte('\n')
	}
	return body.Bytes(), nil
}

func commitNDJSONLine(operation CommitOperation) map[string]any {
	key, value := commitNDJSONEntry(operation)
	return map[string]any{"key": key, "value": value}
}

func commitNDJSONEntry(operation CommitOperation) (string, map[string]any) {
	switch operation.Kind {
	case CommitFile:
		return "file", map[string]any{"content": base64.StdEncoding.EncodeToString(operation.Content), "path": operation.Path, "encoding": "base64"}
	case CommitLFSFile:
		return "lfsFile", map[string]any{"path": operation.Path, "algo": "sha256", "oid": operation.OID, "size": operation.Size}
	case CommitDeletedFile:
		return "deletedFile", map[string]any{"path": operation.Path}
	case CommitDeletedFolder:
		return "deletedFolder", map[string]any{"path": operation.Path}
	default:
		return "", nil
	}
}

type repoPathInfoWire struct {
	Type    string `json:"type"`
	OID     string `json:"oid"`
	Size    int64  `json:"size"`
	Path    string `json:"path"`
	XetHash string `json:"xetHash"`
	LFS     struct {
		SHA256 string `json:"sha256"`
	} `json:"lfs"`
}

func escapeRepoPath(path string) string {
	parts := strings.Split(path, "/")
	for index := range parts {
		parts[index] = url.PathEscape(parts[index])
	}
	return strings.Join(parts, "/")
}

func (c *Client) trustedContentLocation(location *url.URL) bool {
	if !validContentLocationShape(location) {
		return false
	}
	base, err := url.Parse(c.base)
	if err == nil && sameOrigin(location, base) {
		return true
	}
	host := strings.ToLower(location.Hostname())
	return location.Scheme == "https" && trustedContentHost(host) && location.Port() == ""
}

func validContentLocationShape(location *url.URL) bool {
	return location != nil && location.User == nil && location.Fragment == ""
}

func sameOrigin(left, right *url.URL) bool {
	return left.Scheme == right.Scheme && left.Host == right.Host
}

func trustedContentHost(host string) bool {
	return host == "hf.co" ||
		strings.HasSuffix(host, ".hf.co") ||
		host == "huggingface.co" ||
		strings.HasSuffix(host, ".huggingface.co")
}
