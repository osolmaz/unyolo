package hubclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	maxBucketBatchOperations = 1000
	maxBucketObjectBytes     = int64(512 << 20)
)

func (c *Client) BucketInfo(ctx context.Context, ref BucketRef) (BucketInfo, error) {
	if err := ref.Validate(); err != nil {
		return BucketInfo{}, err
	}
	var info BucketInfo
	if err := c.call(ctx, callSpec{method: http.MethodGet, path: ref.apiPath(), out: &info}); err != nil {
		return BucketInfo{}, err
	}
	if info.ID != ref.ID() {
		return BucketInfo{}, &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
	}
	return info, nil
}

// ListBuckets returns one bounded Hub page for an exact namespace.
func (c *Client) ListBuckets(ctx context.Context, namespace, search string, limit int) ([]BucketInfo, error) {
	if err := (BucketRef{Namespace: namespace, Name: "probe"}).Validate(); err != nil || limit < 1 || limit > 100 || len(search) > 128 || strings.ContainsRune(search, 0) {
		return nil, errors.New("hubclient: bucket list query is invalid")
	}
	query := url.Values{"limit": {strconv.Itoa(limit)}}
	if search != "" {
		query.Set("search", search)
	}
	var values []BucketInfo
	if err := c.call(ctx, callSpec{method: http.MethodGet, path: "/api/buckets/" + url.PathEscape(namespace), query: query, out: &values}); err != nil {
		return nil, err
	}
	if len(values) > limit {
		return nil, &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
	}
	for _, value := range values {
		if err := validateBucketInfo(value); err != nil {
			return nil, err
		}
	}
	return values, nil
}

// ListBucketTree returns one bounded object tree page.
func (c *Client) ListBucketTree(ctx context.Context, ref BucketRef, prefix string, recursive bool, limit int) ([]BucketTreeEntry, error) {
	if err := ref.Validate(); err != nil || !validBucketPrefix(prefix) || limit < 1 || limit > 1000 {
		return nil, errors.New("hubclient: bucket tree query is invalid")
	}
	path := ref.apiPath("tree")
	if prefix != "" {
		path += "/" + url.PathEscape(prefix)
	}
	var values []BucketTreeEntry
	if err := c.call(ctx, callSpec{method: http.MethodGet, path: path,
		query: url.Values{"recursive": {strconv.FormatBool(recursive)}, "limit": {strconv.Itoa(limit)}}, out: &values}); err != nil {
		return nil, err
	}
	if len(values) > limit || validateBucketTree(values) != nil {
		return nil, &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
	}
	return values, nil
}

// BucketObjectInfo returns metadata for one exact object path.
func (c *Client) BucketObjectInfo(ctx context.Context, ref BucketRef, path string) (BucketTreeEntry, error) {
	if err := ref.Validate(); err != nil || !validObjectPath(path) {
		return BucketTreeEntry{}, errors.New("hubclient: bucket object identity is invalid")
	}
	var values []BucketTreeEntry
	if err := c.call(ctx, callSpec{method: http.MethodPost, path: ref.apiPath("paths-info"), body: map[string]any{"paths": []string{path}}, out: &values}); err != nil {
		return BucketTreeEntry{}, err
	}
	if len(values) == 0 {
		return BucketTreeEntry{}, &Error{Code: CodeNotFound, StatusCode: http.StatusNotFound}
	}
	if len(values) != 1 || values[0].Path != path || validateBucketTree(values) != nil || values[0].Type != "file" {
		return BucketTreeEntry{}, &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
	}
	return values[0], nil
}

// ReadBucketObject reads one small bounded exact object and strips the broker
// token from trusted content redirects.
func (c *Client) ReadBucketObject(ctx context.Context, ref BucketRef, path string) (BucketObject, error) {
	reader, err := c.OpenBucketObject(ctx, ref, path)
	if err != nil {
		return BucketObject{}, err
	}
	defer func() { _ = reader.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(reader.Body, c.maxResponseBytes+1))
	if err != nil {
		return BucketObject{}, &Error{Code: CodeUnavailable}
	}
	if int64(len(payload)) > c.maxResponseBytes {
		return BucketObject{}, &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
	}
	return BucketObject{Path: path, Content: payload, ContentType: reader.ContentType}, nil
}

// OpenBucketObject opens one bounded exact object for streaming.
func (c *Client) OpenBucketObject(ctx context.Context, ref BucketRef, path string) (BucketObjectReader, error) {
	if err := ref.Validate(); err != nil || !validObjectPath(path) {
		return BucketObjectReader{}, errors.New("hubclient: bucket object identity is invalid")
	}
	requestContext, cancel := c.callContext(ctx)
	request, err := c.newRequest(requestContext, callSpec{method: http.MethodGet, path: "/buckets/" + url.PathEscape(ref.Namespace) + "/" + url.PathEscape(ref.Name) + "/resolve/" + url.PathEscape(path)})
	if err != nil {
		cancel()
		return BucketObjectReader{}, err
	}
	client := &http.Client{Transport: c.httpClient.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		cancel()
		return BucketObjectReader{}, &Error{Code: CodeUnavailable}
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		response, err = c.followRepoFileRedirect(requestContext, client, response)
		if err != nil {
			cancel()
			return BucketObjectReader{}, err
		}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || response.ContentLength > maxBucketObjectBytes {
		_ = response.Body.Close()
		cancel()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return BucketObjectReader{}, statusError(response.StatusCode, response.Header)
		}
		return BucketObjectReader{}, &Error{Code: CodeResponseInvalid, StatusCode: response.StatusCode}
	}
	mediaType := strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0])
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	return BucketObjectReader{Body: &cancelReadCloser{ReadCloser: response.Body, cancel: cancel}, Size: response.ContentLength, ContentType: mediaType}, nil
}

type cancelReadCloser struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (reader *cancelReadCloser) Close() error {
	err := reader.ReadCloser.Close()
	reader.cancel()
	return err
}

func validateBucketInfo(info BucketInfo) error {
	parts := strings.Split(info.ID, "/")
	if len(parts) != 2 || !ValidNamespaceSegment(parts[0]) || !ValidNamespaceSegment(parts[1]) || info.Private == nil || info.Size < 0 || info.TotalFiles < 0 {
		return &Error{Code: CodeResponseInvalid, StatusCode: http.StatusOK}
	}
	return nil
}

func validBucketPrefix(prefix string) bool {
	return prefix == "" || validObjectPath(strings.TrimSuffix(prefix, "/"))
}

func validateBucketTree(values []BucketTreeEntry) error {
	for _, value := range values {
		if !validObjectPath(value.Path) || value.Size < 0 {
			return errors.New("hubclient: upstream bucket tree is invalid")
		}
		switch value.Type {
		case "file":
			if !validXetHash(strings.ToLower(value.XetHash)) {
				return errors.New("hubclient: upstream bucket tree is invalid")
			}
		case "directory":
			if value.XetHash != "" || value.Size != 0 {
				return errors.New("hubclient: upstream bucket tree is invalid")
			}
		default:
			return errors.New("hubclient: upstream bucket tree is invalid")
		}
	}
	return nil
}

func (c *Client) ApplyBucketBatch(ctx context.Context, ref BucketRef, operations []BucketBatchOperation) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	if err := ValidateBucketBatchOperations(operations); err != nil {
		return err
	}
	body, err := bucketBatchNDJSON(operations)
	if err != nil {
		return err
	}
	var result mutationBatchResult
	if err := c.call(ctx, callSpec{method: http.MethodPost, path: ref.apiPath("batch"), rawBody: body, contentType: "application/x-ndjson", out: &result}); err != nil {
		return err
	}
	if !batchMutationSucceeded(result, len(operations)) {
		return &Error{Code: CodeResultUnknown, StatusCode: http.StatusOK, Ambiguous: true}
	}
	return nil
}

func bucketBatchNDJSON(operations []BucketBatchOperation) ([]byte, error) {
	var body bytes.Buffer
	for _, operation := range operations {
		line, err := json.Marshal(operation)
		if err != nil || body.Len()+len(line)+1 > maxRequestBodyBytes {
			return nil, errors.New("hubclient: bucket batch body is invalid")
		}
		body.Write(line)
		body.WriteByte('\n')
	}
	return body.Bytes(), nil
}

func batchMutationSucceeded(result mutationBatchResult, expected int) bool {
	return result.Success &&
		result.Processed == expected &&
		result.Succeeded == expected &&
		len(result.Failed) == 0
}

func ValidateBucketBatchOperations(operations []BucketBatchOperation) error {
	if len(operations) == 0 || len(operations) > maxBucketBatchOperations {
		return errors.New("hubclient: bucket batch size is invalid")
	}
	deleting := false
	for _, operation := range operations {
		if err := validateBucketBatchOperation(operation); err != nil {
			return err
		}
		if operation.Type == "deleteFile" {
			deleting = true
		} else if deleting {
			return errors.New("hubclient: bucket deletes must follow add and copy operations")
		}
	}
	return nil
}

func (c *Client) MoveBucket(ctx context.Context, from, to BucketRef) error {
	if err := from.Validate(); err != nil {
		return err
	}
	if err := to.Validate(); err != nil || from == to {
		return errors.New("hubclient: bucket destination is invalid")
	}
	body := struct {
		FromRepo string `json:"fromRepo"`
		ToRepo   string `json:"toRepo"`
		Type     string `json:"type"`
	}{FromRepo: from.ID(), ToRepo: to.ID(), Type: "bucket"}
	return c.call(ctx, callSpec{method: http.MethodPost, path: "/api/repos/move", body: body})
}

func validateBucketBatchOperation(operation BucketBatchOperation) error {
	if !validObjectPath(operation.Path) {
		return errors.New("hubclient: bucket object path is invalid")
	}
	switch operation.Type {
	case "addFile":
		return validateBucketAddOperation(operation)
	case "copyFile":
		return validateBucketCopyOperation(operation)
	case "deleteFile":
		return validateBucketDeleteOperation(operation)
	default:
		return errors.New("hubclient: bucket operation type is invalid")
	}
}

func validateBucketAddOperation(operation BucketBatchOperation) error {
	if !validXetHash(operation.XetHash) || operation.MTime <= 0 || len(operation.ContentType) > 255 ||
		operation.SourceRepoType != "" || operation.SourceRepoID != "" {
		return errors.New("hubclient: bucket add operation is invalid")
	}
	return nil
}

func validateBucketCopyOperation(operation BucketBatchOperation) error {
	if !validXetHash(operation.XetHash) || operation.MTime != 0 || operation.ContentType != "" ||
		!validSourceRepo(operation.SourceRepoType, operation.SourceRepoID) {
		return errors.New("hubclient: bucket copy operation is invalid")
	}
	return nil
}

func validateBucketDeleteOperation(operation BucketBatchOperation) error {
	if operation.XetHash != "" || operation.MTime != 0 || operation.ContentType != "" ||
		operation.SourceRepoType != "" || operation.SourceRepoID != "" {
		return errors.New("hubclient: bucket delete operation is invalid")
	}
	return nil
}

func validObjectPath(value string) bool {
	if invalidObjectPathShape(value) {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func invalidObjectPathShape(value string) bool {
	return value == "" ||
		len(value) > 1024 ||
		strings.HasPrefix(value, "/") ||
		strings.HasSuffix(value, "/") ||
		strings.Contains(value, "\\") ||
		strings.ContainsRune(value, 0)
}

func validXetHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if !strings.ContainsRune("0123456789abcdef", char) {
			return false
		}
	}
	return true
}

func validSourceRepo(repoType, repoID string) bool {
	if repoType != "model" && repoType != "dataset" && repoType != "space" && repoType != "bucket" {
		return false
	}
	parts := strings.Split(repoID, "/")
	return len(parts) == 2 && ValidNamespaceSegment(parts[0]) && ValidNamespaceSegment(parts[1]) && url.PathEscape(repoID) != ""
}

type mutationBatchResult struct {
	Success   bool             `json:"success"`
	Processed int              `json:"processed"`
	Succeeded int              `json:"succeeded"`
	Failed    []map[string]any `json:"failed"`
}
