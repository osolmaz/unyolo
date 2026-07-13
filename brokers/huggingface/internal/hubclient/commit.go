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
	query := make(url.Values)
	if request.CreatePR {
		query.Set("create_pr", "1")
	}
	if request.HotReload {
		query.Set("hot_reload", "1")
	}
	var result CommitResult
	path := request.Ref.apiPath("commit", url.PathEscape(request.Revision))
	if err := c.call(ctx, callSpec{method: http.MethodPost, path: path, query: query, rawBody: body, contentType: "application/x-ndjson", out: &result}); err != nil {
		return CommitResult{}, err
	}
	if !commitOIDPattern.MatchString(result.CommitOID) || result.CommitURL == "" {
		return CommitResult{}, &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
	}
	return result, nil
}

//nolint:cyclop // Response bounds are explicit and tracked by the exact HF CRAP baseline.
func (c *Client) RepoPathsInfo(ctx context.Context, ref RepoRef, revision string, paths []string) ([]RepoPathInfo, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	if !ValidGitRefComponent(revision) || len(paths) == 0 || len(paths) > 500 {
		return nil, errors.New("hubclient: repository paths request is invalid")
	}
	for _, path := range paths {
		if !ValidRepoPath(path, false) {
			return nil, errors.New("hubclient: repository path is invalid")
		}
	}
	body := struct {
		Paths  []string `json:"paths"`
		Expand bool     `json:"expand"`
	}{Paths: paths, Expand: false}
	var wire []repoPathInfoWire
	if err := c.call(ctx, callSpec{method: http.MethodPost, path: ref.apiPath("paths-info", url.PathEscape(revision)), body: body, out: &wire}); err != nil {
		return nil, err
	}
	result := make([]RepoPathInfo, 0, len(wire))
	for _, item := range wire {
		if !ValidRepoPath(item.Path, item.Type == "directory") || item.OID == "" || item.Size < 0 {
			return nil, &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
		}
		result = append(result, RepoPathInfo{Type: item.Type, Path: item.Path, OID: item.OID, Size: item.Size, LFSSHA: item.LFS.SHA256, XetHash: item.XetHash})
	}
	return result, nil
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

//nolint:cyclop // Redirect and response checks are explicit and tracked by the exact HF CRAP baseline.
func (c *Client) ReadRepoFile(ctx context.Context, ref RepoRef, revision, path string) ([]byte, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	if !ValidGitRefComponent(revision) || !ValidRepoPath(path, false) {
		return nil, errors.New("hubclient: repository file identity is invalid")
	}
	prefix := ""
	if ref.Type != RepoTypeModel {
		prefix = "/" + string(ref.Type) + "s"
	}
	requestPath := prefix + "/" + url.PathEscape(ref.Owner) + "/" + url.PathEscape(ref.Name) + "/resolve/" + url.PathEscape(revision) + "/" + escapeRepoPath(path)
	request, err := c.newRequest(ctx, callSpec{method: http.MethodGet, path: requestPath})
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: c.httpClient.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return nil, &Error{Code: CodeUnavailable}
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		location, parseErr := response.Location()
		if parseErr != nil || !c.trustedContentLocation(location) {
			return nil, &Error{Code: CodeResponseInvalid, StatusCode: response.StatusCode}
		}
		_ = response.Body.Close()
		redirect, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, location.String(), nil)
		if requestErr != nil {
			return nil, errors.New("hubclient: content redirect is invalid")
		}
		redirect.Header.Set("Accept", "application/octet-stream")
		response, err = client.Do(redirect)
		if err != nil {
			return nil, &Error{Code: CodeUnavailable}
		}
		defer func() { _ = response.Body.Close() }()
	}
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

//nolint:cyclop // LFS copy checks are explicit and tracked by the exact HF CRAP baseline.
func (c *Client) DuplicateLFSFile(ctx context.Context, source, destination RepoRef, info RepoPathInfo) error {
	if err := source.Validate(); err != nil {
		return err
	}
	if err := destination.Validate(); err != nil {
		return err
	}
	if !validXetHash(strings.ToLower(info.XetHash)) || !validXetHash(strings.ToLower(info.LFSSHA)) || !ValidRepoPath(info.Path, false) {
		return errors.New("hubclient: LFS source metadata is invalid")
	}
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
	var result mutationBatchResult
	if err := c.call(ctx, callSpec{method: http.MethodPost, path: source.apiPath("lfs-files", "duplicate"), body: body, out: &result}); err != nil {
		return err
	}
	if !result.Success || result.Processed != 1 || result.Succeeded != 1 || len(result.Failed) != 0 {
		return &Error{Code: CodeInvalid, StatusCode: http.StatusOK}
	}
	return nil
}

//nolint:cyclop // Repository path constraints are explicit and tracked by the exact HF CRAP baseline.
func ValidRepoPath(value string, folder bool) bool {
	if value == "" || len(value) > 1000 || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") || strings.ContainsRune(value, 0) {
		return false
	}
	trimmed := strings.TrimSuffix(value, "/")
	if folder != strings.HasSuffix(value, "/") || trimmed == "" {
		return false
	}
	for _, part := range strings.Split(trimmed, "/") {
		if part == "" || part == "." || part == ".." || part == ".git" {
			return false
		}
	}
	return true
}

//nolint:cyclop // Commit-kind validation is explicit and tracked by the exact HF CRAP baseline.
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
		switch operation.Kind {
		case CommitFile:
			if operation.Content == nil || operation.OID != "" || operation.Size != 0 {
				return errors.New("hubclient: regular file operation is invalid")
			}
		case CommitLFSFile:
			if operation.Content != nil || !validXetHash(strings.ToLower(operation.OID)) || operation.Size < 0 {
				return errors.New("hubclient: LFS file operation is invalid")
			}
		case CommitDeletedFile, CommitDeletedFolder:
			if operation.Content != nil || operation.OID != "" || operation.Size != 0 {
				return errors.New("hubclient: delete operation is invalid")
			}
		default:
			return errors.New("hubclient: commit operation type is invalid")
		}
	}
	return nil
}

func validateCommitRequest(request CommitRequest) error {
	if err := request.Ref.Validate(); err != nil {
		return err
	}
	if !ValidGitRefComponent(request.Revision) || strings.TrimSpace(request.Summary) == "" || len(request.Summary) > 500 || len(request.Description) > 10_000 ||
		(request.ParentCommit != "" && !commitOIDPattern.MatchString(request.ParentCommit)) || request.HotReload && request.Ref.Type != RepoTypeSpace {
		return errors.New("hubclient: commit metadata is invalid")
	}
	return ValidateCommitOperations(request.Operations)
}

func commitNDJSON(request CommitRequest) ([]byte, error) {
	header := map[string]any{"summary": request.Summary, "description": request.Description}
	if request.ParentCommit != "" {
		header["parentCommit"] = request.ParentCommit
	}
	lines := []any{map[string]any{"key": "header", "value": header}}
	for _, operation := range request.Operations {
		var key string
		var value map[string]any
		switch operation.Kind {
		case CommitFile:
			key = "file"
			value = map[string]any{"content": base64.StdEncoding.EncodeToString(operation.Content), "path": operation.Path, "encoding": "base64"}
		case CommitLFSFile:
			key = "lfsFile"
			value = map[string]any{"path": operation.Path, "algo": "sha256", "oid": operation.OID, "size": operation.Size}
		case CommitDeletedFile:
			key, value = "deletedFile", map[string]any{"path": operation.Path}
		case CommitDeletedFolder:
			key, value = "deletedFolder", map[string]any{"path": operation.Path}
		}
		lines = append(lines, map[string]any{"key": key, "value": value})
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

//nolint:cyclop // Redirect trust checks are explicit and tracked by the exact HF CRAP baseline.
func (c *Client) trustedContentLocation(location *url.URL) bool {
	if location == nil || location.User != nil || location.Fragment != "" {
		return false
	}
	base, err := url.Parse(c.base)
	if err == nil && location.Scheme == base.Scheme && location.Host == base.Host {
		return true
	}
	host := strings.ToLower(location.Hostname())
	return location.Scheme == "https" && (host == "hf.co" || strings.HasSuffix(host, ".hf.co") || host == "huggingface.co" || strings.HasSuffix(host, ".huggingface.co")) && location.Port() == ""
}
