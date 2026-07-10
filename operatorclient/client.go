// Package operatorclient is a small Go client for the Brokerkit operator API.
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

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operatorinbox"
)

const maxResponseBytes = 2 * 1024 * 1024

// Client calls one protected operator API.
type Client struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

// Error is one stable safe API error.
type Error struct {
	Status  int
	Code    string
	Message string
	Current *operatorinbox.Item
}

func (e *Error) Error() string {
	return fmt.Sprintf("operator API %s (%d): %s", e.Code, e.Status, e.Message)
}

// Decision supplies optimistic concurrency and optional narrowing values.
type Decision struct {
	ExpectedRevision int64
	ExpectedStatus   grants.Status
	Reason           string
	Duration         time.Duration
	MaxUses          int
}

type receiverError struct{ error }

// List returns one bounded operator-inbox page.
func (c *Client) List(ctx context.Context, query grants.Query) (operatorinbox.Page, error) {
	values := encodeQuery(query)
	var page operatorinbox.Page
	err := c.doJSON(ctx, http.MethodGet, "/api/grants?"+values.Encode(), nil, &page)
	return page, err
}

func encodeQuery(query grants.Query) url.Values {
	values := make(url.Values)
	setNonempty(values, "status", string(query.StatusGroup))
	setNonempty(values, "client", query.Client)
	setNonempty(values, "operation", query.Operation)
	setNonempty(values, "cursor", query.Cursor)
	setNonempty(values, "limit", nonzeroInt(query.Limit))
	if query.Target != nil {
		values.Set("target_kind", query.Target.Kind)
		for key, list := range query.Target.Fields {
			for _, value := range list {
				values.Add("target."+key, value)
			}
		}
	}
	return values
}

func setNonempty(values url.Values, key string, value string) {
	if value != "" {
		values.Set(key, value)
	}
}

func nonzeroInt(value int) string {
	if value == 0 {
		return ""
	}
	return strconv.Itoa(value)
}

// Get returns one operator-safe inbox item.
func (c *Client) Get(ctx context.Context, id string) (operatorinbox.Item, error) {
	var item operatorinbox.Item
	err := c.doJSON(ctx, http.MethodGet, "/api/grants/"+url.PathEscape(id), nil, &item)
	return item, err
}

func (c *Client) Approve(ctx context.Context, id string, decision Decision) (operatorinbox.Item, error) {
	return c.decide(ctx, id, "approve", decision)
}

func (c *Client) Deny(ctx context.Context, id string, decision Decision) (operatorinbox.Item, error) {
	return c.decide(ctx, id, "deny", decision)
}

func (c *Client) Cancel(ctx context.Context, id string, decision Decision) (operatorinbox.Item, error) {
	return c.decide(ctx, id, "cancel", decision)
}

func (c *Client) Revoke(ctx context.Context, id string, decision Decision) (operatorinbox.Item, error) {
	return c.decide(ctx, id, "revoke", decision)
}

func (c *Client) decide(ctx context.Context, id string, action string, decision Decision) (operatorinbox.Item, error) {
	body := struct {
		ExpectedRevision int64         `json:"expected_revision"`
		ExpectedStatus   grants.Status `json:"expected_status,omitempty"`
		Reason           string        `json:"reason,omitempty"`
		DurationSeconds  int64         `json:"duration_seconds,omitempty"`
		MaxUses          int           `json:"max_uses,omitempty"`
	}{decision.ExpectedRevision, decision.ExpectedStatus, decision.Reason, int64(decision.Duration / time.Second), decision.MaxUses}
	var item operatorinbox.Item
	err := c.doJSON(ctx, http.MethodPost, "/api/grants/"+url.PathEscape(id)+"/"+action, body, &item)
	return item, err
}

// StreamEvents reconnects from the last durable cursor until ctx is canceled.
func (c *Client) StreamEvents(ctx context.Context, cursor string, receive func(grants.Event) error) error {
	if receive == nil {
		return errors.New("event receiver is required")
	}
	backoff := 100 * time.Millisecond
	for {
		last, err := c.streamOnce(ctx, cursor, receive)
		if last != "" {
			cursor = last
		}
		if terminal := terminalStreamError(ctx, err); terminal != nil {
			return terminal
		}
		if err := waitForReconnect(ctx, backoff); err != nil {
			return err
		}
		if backoff < 2*time.Second {
			backoff *= 2
		}
	}
}

func terminalStreamError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var callbackErr receiverError
	if errors.As(err, &callbackErr) {
		return callbackErr.error
	}
	var apiErr *Error
	if errors.As(err, &apiErr) && (apiErr.Status == http.StatusBadRequest || apiErr.Status == http.StatusGone) {
		return err
	}
	return nil
}

func waitForReconnect(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *Client) streamOnce(ctx context.Context, cursor string, receive func(grants.Event) error) (string, error) {
	response, err := c.openEventStream(ctx, cursor)
	if err != nil {
		return cursor, err
	}
	defer func() { _ = response.Body.Close() }()
	return consumeEventStream(response.Body, cursor, receive)
}

func (c *Client) openEventStream(ctx context.Context, cursor string) (*http.Response, error) {
	endpoint := "/api/grants/events"
	if cursor != "" {
		endpoint += "?cursor=" + url.QueryEscape(cursor)
	}
	request, err := c.newRequest(ctx, http.MethodGet, endpoint, nil)
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
	return response, nil
}

func consumeEventStream(reader io.Reader, cursor string, receive func(grants.Event) error) (string, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4*1024), 128*1024)
	decoder := sseDecoder{}
	for scanner.Scan() {
		event, err := decoder.addLine(scanner.Text())
		if err != nil {
			return cursor, err
		}
		if event != nil {
			if err := receive(*event); err != nil {
				return cursor, receiverError{err}
			}
			cursor = event.Cursor
		}
	}
	return cursor, scanner.Err()
}

type sseDecoder struct {
	eventID string
	data    strings.Builder
}

func (d *sseDecoder) addLine(line string) (*grants.Event, error) {
	switch {
	case strings.HasPrefix(line, "id:"):
		d.eventID = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
	case strings.HasPrefix(line, "data:"):
		if d.data.Len() > 0 {
			d.data.WriteByte('\n')
		}
		d.data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
	case line == "":
		return d.finishEvent()
	}
	return nil, nil
}

func (d *sseDecoder) finishEvent() (*grants.Event, error) {
	if d.data.Len() == 0 {
		return nil, nil
	}
	var event grants.Event
	if err := json.Unmarshal([]byte(d.data.String()), &event); err != nil {
		return nil, fmt.Errorf("decode operator event: %w", err)
	}
	if d.eventID == "" || event.Cursor != d.eventID {
		return nil, errors.New("operator event cursor mismatch")
	}
	d.eventID = ""
	d.data.Reset()
	return &event, nil
}

func (c *Client) doJSON(ctx context.Context, method string, path string, body any, target any) error {
	encoded, err := encodeJSONBody(body)
	if err != nil {
		return err
	}
	request, err := c.newRequest(ctx, method, path, encoded)
	if err != nil {
		return err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient().Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return decodeAPIError(response)
	}
	return decodeJSONResponse(response.Body, target)
}

func encodeJSONBody(body any) (io.Reader, error) {
	if body == nil {
		return nil, nil
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(data), nil
}

func decodeJSONResponse(body io.Reader, target any) error {
	decoder := json.NewDecoder(io.LimitReader(body, maxResponseBytes))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode operator response: %w", err)
	}
	return nil
}

func (c *Client) newRequest(ctx context.Context, method string, path string, body io.Reader) (*http.Request, error) {
	base := strings.TrimSuffix(c.BaseURL, "/")
	if base == "" {
		return nil, errors.New("operator API base URL is required")
	}
	request, err := http.NewRequestWithContext(ctx, method, base+path, body)
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
	return http.DefaultClient
}

func decodeAPIError(response *http.Response) error {
	var envelope struct {
		Error struct {
			Code    string              `json:"code"`
			Message string              `json:"message"`
			Current *operatorinbox.Item `json:"current"`
		} `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes)).Decode(&envelope); err != nil {
		return &Error{Status: response.StatusCode, Code: "http_error", Message: http.StatusText(response.StatusCode)}
	}
	return &Error{Status: response.StatusCode, Code: envelope.Error.Code, Message: envelope.Error.Message, Current: envelope.Error.Current}
}
