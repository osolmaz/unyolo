package agentclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/httpx"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/sealedstore"
	"github.com/osolmaz/brokerkit/streamstore"
)

const (
	maxTransferReferenceBytes = 64 << 10
	maxSealedPayloadBytes     = 1 << 20
)

// UploadSealedPayload sends one bounded opaque payload to the broker's
// one-time sealed store and validates its request binding.
func (c *Client) UploadSealedPayload(ctx context.Context, operation, requestKey string, payload []byte) (sealedstore.Reference, error) {
	if !validTransferBinding(operation, requestKey) || len(payload) == 0 || len(payload) > maxSealedPayloadBytes {
		return sealedstore.Reference{}, errors.New("sealed payload is invalid")
	}
	response, err := c.upload(ctx, "/api/agent/v1/sealed-payloads", operation, requestKey,
		bytes.NewReader(payload), int64(len(payload)), "application/octet-stream")
	if err != nil {
		return sealedstore.Reference{}, err
	}
	defer func() { _ = response.Body.Close() }()
	var reference sealedstore.Reference
	if err := decodeTransferReference(response, &reference); err != nil || reference.ID == "" ||
		reference.Purpose != operation || reference.RequestKey != requestKey {
		return sealedstore.Reference{}, errors.New("broker returned an invalid sealed payload reference")
	}
	return reference, nil
}

// UploadStream sends a caller-bounded stream and validates its operation and
// retry binding. Providers remain responsible for choosing the byte limit.
func (c *Client) UploadStream(ctx context.Context, operation, requestKey, mediaType string, source io.Reader, size, limit int64) (streamstore.Reference, error) {
	if !validTransferBinding(operation, requestKey) || source == nil || size < 1 || limit < 1 || size > limit ||
		strings.TrimSpace(mediaType) == "" || len(mediaType) > 255 {
		return streamstore.Reference{}, errors.New("stream upload is invalid")
	}
	response, err := c.upload(ctx, "/api/agent/v1/streams", operation, requestKey, io.LimitReader(source, limit+1), size, mediaType)
	if err != nil {
		return streamstore.Reference{}, err
	}
	defer func() { _ = response.Body.Close() }()
	var reference streamstore.Reference
	if err := decodeTransferReference(response, &reference); err != nil || reference.ID == "" || reference.Owner == "" ||
		reference.Purpose != operation || reference.RequestKey != requestKey || reference.Size != size {
		return streamstore.Reference{}, errors.New("broker returned an invalid stream reference")
	}
	return reference, nil
}

// DownloadStream copies one bounded stream while verifying the broker's exact
// length and SHA-256 response metadata.
func (c *Client) DownloadStream(ctx context.Context, id string, destination io.Writer, limit int64) (int64, error) {
	if destination == nil || limit < 1 || !strings.HasPrefix(id, "stream_") {
		return 0, errors.New("stream download is invalid")
	}
	request, err := c.request(ctx, http.MethodGet, "/api/agent/v1/streams/"+url.PathEscape(id), http.NoBody, 0, "")
	if err != nil {
		return 0, err
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return 0, errors.New("download stream")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || response.ContentLength < 1 || response.ContentLength > limit {
		return 0, errors.New("broker rejected stream download")
	}
	expected, err := hex.DecodeString(response.Header.Get("X-Broker-Content-SHA256"))
	if err != nil || len(expected) != sha256.Size {
		return 0, errors.New("broker returned invalid stream integrity metadata")
	}
	digest := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(destination, digest), io.LimitReader(response.Body, limit+1))
	if copyErr != nil || written != response.ContentLength || subtle.ConstantTimeCompare(digest.Sum(nil), expected) != 1 {
		return 0, errors.New("stream download failed integrity validation")
	}
	return written, nil
}

func (c *Client) upload(ctx context.Context, path, operation, requestKey string, body io.Reader, size int64, mediaType string) (*http.Response, error) {
	request, err := c.request(ctx, http.MethodPost, path, body, size, mediaType)
	if err != nil {
		return nil, err
	}
	request.Header.Set("X-Broker-Operation", operation)
	request.Header.Set("X-Broker-Idempotency-Key", requestKey)
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, errors.New("upload broker payload")
	}
	return response, nil
}

func (c *Client) request(ctx context.Context, method, path string, body io.Reader, size int64, mediaType string) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.baseURL, "/")+path, body)
	if err != nil {
		return nil, errors.New("create agent transfer request")
	}
	request.Header.Set("Authorization", "Bearer "+c.credential)
	if size > 0 {
		request.ContentLength = size
		request.Header.Set("Content-Type", mediaType)
	}
	return request, nil
}

func decodeTransferReference(response *http.Response, target any) error {
	data, err := httpx.ReadLimited(response.Body, maxTransferReferenceBytes)
	if err != nil || response.StatusCode != http.StatusCreated || strictjson.Decode(data, target, true) != nil {
		return errors.New("broker rejected payload upload with HTTP " + strconv.Itoa(response.StatusCode))
	}
	return nil
}

func validTransferBinding(operation, requestKey string) bool {
	return len(operation) <= 128 && strings.Contains(operation, ".") && agentv1.ValidIdempotencyKey(requestKey)
}
