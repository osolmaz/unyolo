// Package upstreamdrift monitors the official Hugging Face OpenAPI surface.
package upstreamdrift

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/osolmaz/brokerkit/internal/openapidrift"
)

const (
	SourceURL        = "https://huggingface.co/.well-known/openapi.json"
	maxDocumentBytes = 32 << 20
	userAgent        = "brokerkit-huggingface-capability-monitor"
)

// Change is one structural difference from the reviewed OpenAPI snapshot.
type Change = openapidrift.Change

// Source identifies the live document used for one comparison.
type Source struct {
	URL         string
	SHA256      string
	RetrievedAt time.Time
}

// Report is a bounded, deterministic capability drift result.
type Report struct {
	Source  Source
	Changes []Change
}

// HasDrift reports whether the live document differs structurally.
func (r Report) HasDrift() bool { return len(r.Changes) != 0 }

// Analyze compares a reviewed document with one bounded live snapshot.
func Analyze(pinned, current []byte, source Source) (Report, error) {
	changes, err := openapidrift.Analyze(pinned, current)
	if err != nil {
		return Report{}, err
	}
	return Report{Source: source, Changes: slices.Clone(changes)}, nil
}

// Client fetches the fixed official Hugging Face OpenAPI document.
type Client struct {
	http *http.Client
	now  func() time.Time
	url  string
}

// NewClient returns a bounded client that refuses redirects.
func NewClient() *Client {
	return &Client{
		http: &http.Client{
			Timeout: 90 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("upstream redirect refused")
			},
		},
		now: time.Now,
		url: SourceURL,
	}
}

// FetchCurrent retrieves the live schema with fixed size and origin bounds.
func (c *Client) FetchCurrent(ctx context.Context) ([]byte, Source, error) {
	if c == nil || c.http == nil || c.now == nil || c.url == "" {
		return nil, Source{}, errors.New("upstream metadata client is not configured")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, Source{}, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", userAgent)
	response, err := c.http.Do(request)
	if err != nil {
		return nil, Source{}, fmt.Errorf("fetch official Hugging Face OpenAPI document: %w", err)
	}
	data, source, readErr := readDocument(response, c.now().UTC())
	return data, source, errors.Join(readErr, response.Body.Close())
}

func readDocument(response *http.Response, retrievedAt time.Time) ([]byte, Source, error) {
	if response.StatusCode != http.StatusOK {
		return nil, Source{}, fmt.Errorf("official Hugging Face OpenAPI document returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxDocumentBytes+1))
	if err != nil {
		return nil, Source{}, errors.New("read official Hugging Face OpenAPI document")
	}
	if len(data) == 0 || len(data) > maxDocumentBytes {
		return nil, Source{}, errors.New("official Hugging Face OpenAPI document has an invalid size")
	}
	digest := sha256.Sum256(data)
	source := Source{
		URL:         SourceURL,
		SHA256:      hex.EncodeToString(digest[:]),
		RetrievedAt: retrievedAt,
	}
	return data, source, nil
}
