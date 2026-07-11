// Package operatorclient implements the BrokerKit Operator V1 Source contract.
package operatorclient

import (
	"bufio"
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

	"github.com/osolmaz/brokerkit/operatorv1"
)

const maxResponseBytes = 2 * 1024 * 1024

type Client struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

type Error struct {
	Status        int
	Code          string
	Message       string
	CorrelationID string
	Current       *operatorv1.Request
	RetryAfter    time.Duration
}

func (e *Error) Error() string {
	return fmt.Sprintf("operator API %s (%d): %s", e.Code, e.Status, e.Message)
}

func (c *Client) Discover(ctx context.Context) (operatorv1.Descriptor, error) {
	var descriptor operatorv1.Descriptor
	err := c.doJSON(ctx, http.MethodGet, "/.well-known/brokerkit-operator", nil, &descriptor)
	if err == nil && descriptor.APIVersion != operatorv1.APIVersion {
		return operatorv1.Descriptor{}, fmt.Errorf("unsupported operator API version %q", descriptor.APIVersion)
	}
	return descriptor, err
}

func (c *Client) Health(ctx context.Context) error {
	var status struct {
		Status string `json:"status"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/healthz", nil, &status); err != nil {
		return err
	}
	if status.Status != "ok" {
		return errors.New("operator source is unhealthy")
	}
	return nil
}

func (c *Client) List(ctx context.Context, query operatorv1.Query) (operatorv1.Page, error) {
	values := url.Values{}
	set(values, "status", string(query.Status))
	set(values, "requester", query.Requester)
	set(values, "operation", query.Operation)
	set(values, "cursor", query.Cursor)
	if query.Limit != 0 {
		values.Set("limit", strconv.Itoa(query.Limit))
	}
	if query.Target != nil {
		values.Set("target_kind", query.Target.Kind)
		for key, list := range query.Target.Fields {
			for _, value := range list {
				values.Add("target."+key, value)
			}
		}
	}
	path := "/api/operator/v1/requests"
	if encoded := values.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var page operatorv1.Page
	err := c.doJSON(ctx, http.MethodGet, path, nil, &page)
	return page, err
}

func (c *Client) Get(ctx context.Context, id string) (operatorv1.Request, error) {
	var request operatorv1.Request
	err := c.doJSON(ctx, http.MethodGet, "/api/operator/v1/requests/"+url.PathEscape(id), nil, &request)
	return request, err
}

func (c *Client) Decide(ctx context.Context, id string, action operatorv1.Action, decision operatorv1.Decision) (operatorv1.Request, error) {
	var request operatorv1.Request
	err := c.doJSON(ctx, http.MethodPost, "/api/operator/v1/requests/"+url.PathEscape(id)+"/"+string(action), decision, &request)
	return request, err
}

func (c *Client) Watch(ctx context.Context, cursor string) (operatorv1.EventStream, error) {
	path := "/api/operator/v1/events"
	if cursor != "" {
		path += "?cursor=" + url.QueryEscape(cursor)
	}
	request, err := c.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "text/event-stream")
	response, err := c.httpClient().Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		err := decodeAPIError(response)
		_ = response.Body.Close()
		return nil, err
	}
	return &eventStream{body: response.Body, scanner: newSSEScanner(response.Body)}, nil
}

type eventStream struct {
	body    io.ReadCloser
	scanner *bufio.Scanner
}

func (s *eventStream) Receive(ctx context.Context) (operatorv1.Event, error) {
	type result struct {
		event operatorv1.Event
		err   error
	}
	resultc := make(chan result, 1)
	go func() {
		for s.scanner.Scan() {
			line := s.scanner.Text()
			if strings.HasPrefix(line, ":") {
				continue
			}
			if strings.HasPrefix(line, "data:") {
				var event operatorv1.Event
				err := json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))), &event)
				resultc <- result{event, err}
				return
			}
		}
		resultc <- result{err: s.scanner.Err()}
	}()
	select {
	case <-ctx.Done():
		return operatorv1.Event{}, ctx.Err()
	case result := <-resultc:
		if result.err == nil && result.event.Cursor == "" {
			result.err = errors.New("operator event cursor is required")
		}
		return result.event, result.err
	}
}

func (s *eventStream) Close() error { return s.body.Close() }

func newSSEScanner(reader io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4*1024), 128*1024)
	return scanner
}

func (c *Client) doJSON(ctx context.Context, method, path string, body, target any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := c.newRequest(ctx, method, path, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.httpClient().Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return decodeAPIError(response)
	}
	return decodeBounded(response.Body, target)
}

func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	base, err := url.Parse(c.BaseURL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("operator base URL is invalid")
	}
	relative, err := url.Parse(path)
	if err != nil || !strings.HasPrefix(relative.Path, "/") {
		return nil, errors.New("operator request path is invalid")
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + relative.Path
	base.RawQuery = relative.RawQuery
	request, err := http.NewRequestWithContext(ctx, method, base.String(), body)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		request.Header.Set("Authorization", "Bearer "+c.Token)
	}
	return request, nil
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func decodeAPIError(response *http.Response) error {
	var envelope operatorv1.ErrorEnvelope
	if err := decodeBounded(response.Body, &envelope); err != nil {
		return &Error{Status: response.StatusCode, Code: "internal_error", Message: "invalid operator error response"}
	}
	retry, _ := strconv.Atoi(response.Header.Get("Retry-After"))
	return &Error{Status: response.StatusCode, Code: envelope.Error.Code, Message: envelope.Error.Message,
		CorrelationID: envelope.Error.CorrelationID, Current: envelope.Error.Current, RetryAfter: time.Duration(retry) * time.Second}
}

func decodeBounded(reader io.Reader, target any) error {
	limited := io.LimitReader(reader, maxResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(data) > maxResponseBytes {
		return errors.New("operator response exceeds size limit")
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("decode operator response: %w", err)
	}
	return nil
}

func set(values url.Values, key, value string) {
	if value != "" {
		values.Set(key, value)
	}
}

var _ operatorv1.Source = (*Client)(nil)
