package hubclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

const maxBucketBatchOperations = 1000

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

func (c *Client) ApplyBucketBatch(ctx context.Context, ref BucketRef, operations []BucketBatchOperation) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	if err := ValidateBucketBatchOperations(operations); err != nil {
		return err
	}
	var body bytes.Buffer
	for _, operation := range operations {
		line, err := json.Marshal(operation)
		if err != nil || body.Len()+len(line)+1 > maxRequestBodyBytes {
			return errors.New("hubclient: bucket batch body is invalid")
		}
		body.Write(line)
		body.WriteByte('\n')
	}
	return c.call(ctx, callSpec{method: http.MethodPost, path: ref.apiPath("batch"), rawBody: body.Bytes(), contentType: "application/x-ndjson"})
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
		if !validXetHash(operation.XetHash) || operation.MTime <= 0 || len(operation.ContentType) > 255 ||
			operation.SourceRepoType != "" || operation.SourceRepoID != "" {
			return errors.New("hubclient: bucket add operation is invalid")
		}
	case "copyFile":
		if !validXetHash(operation.XetHash) || operation.MTime != 0 || operation.ContentType != "" ||
			!validSourceRepo(operation.SourceRepoType, operation.SourceRepoID) {
			return errors.New("hubclient: bucket copy operation is invalid")
		}
	case "deleteFile":
		if operation.XetHash != "" || operation.MTime != 0 || operation.ContentType != "" ||
			operation.SourceRepoType != "" || operation.SourceRepoID != "" {
			return errors.New("hubclient: bucket delete operation is invalid")
		}
	default:
		return errors.New("hubclient: bucket operation type is invalid")
	}
	return nil
}

func validObjectPath(value string) bool {
	if value == "" || len(value) > 1024 || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.Contains(value, "\\") || strings.ContainsRune(value, 0) {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
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
