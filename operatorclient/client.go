// Package operatorclient implements the BrokerKit Operator V1 Source contract.
package operatorclient

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/httpx"
	"github.com/osolmaz/brokerkit/internal/optional"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/operatorv1"
	"github.com/osolmaz/brokerkit/operatorv1wire"
	"github.com/osolmaz/brokerkit/protocol/operatorwire"
)

const maxResponseBytes = 2 * 1024 * 1024

type Client struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

// NewUnix returns a Source client connected to an operator-only Unix socket.
func NewUnix(socketPath, token string) (*Client, error) {
	if socketPath == "" || !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath || strings.ContainsRune(socketPath, '\x00') {
		return nil, errors.New("operator Unix socket path is invalid")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	return &Client{
		BaseURL: "http://brokerkit",
		Token:   token,
		HTTPClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
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
	api, err := c.api()
	if err != nil {
		return operatorv1.Descriptor{}, err
	}
	var wire operatorwire.Descriptor
	response, requestErr := api.DiscoverOperator(ctx)
	err = decodeClientResponse(response, requestErr, &wire)
	if err == nil && string(wire.ApiVersion) != operatorv1.APIVersion {
		return operatorv1.Descriptor{}, fmt.Errorf("unsupported operator API version %q", wire.ApiVersion)
	}
	return operatorv1.Descriptor{APIVersion: string(wire.ApiVersion)}, err
}

func (c *Client) Health(ctx context.Context) error {
	api, err := c.api()
	if err != nil {
		return err
	}
	var status operatorwire.Health
	response, requestErr := api.OperatorHealth(ctx)
	if err := decodeClientResponse(response, requestErr, &status); err != nil {
		return err
	}
	if status.Status != "ok" {
		return errors.New("operator source is unhealthy")
	}
	return nil
}

func (c *Client) List(ctx context.Context, query operatorv1.Query) (operatorv1.Page, error) {
	api, err := c.api()
	if err != nil {
		return operatorv1.Page{}, err
	}
	params := operatorwire.ListOperatorRequestsParams{}
	if query.Status != "" {
		value := operatorwire.StatusGroup(query.Status)
		params.Status = &value
	}
	params.Requester = optional.NonZero(query.Requester)
	params.Operation = optional.NonZero(query.Operation)
	params.Cursor = optional.NonZero(query.Cursor)
	if query.Limit != 0 {
		params.Limit = &query.Limit
	}
	var editors []operatorwire.RequestEditorFn
	if query.Target != nil {
		params.TargetKind = &query.Target.Kind
		editors = append(editors, targetQueryEditor(query.Target.Fields))
	}
	var wire operatorwire.RequestPage
	response, requestErr := api.ListOperatorRequests(ctx, &params, editors...)
	err = decodeClientResponse(response, requestErr, &wire)
	return pageFromWire(wire), err
}

func (c *Client) Get(ctx context.Context, id string) (operatorv1.Request, error) {
	api, err := c.api()
	if err != nil {
		return operatorv1.Request{}, err
	}
	var wire operatorwire.BrokerRequest
	response, requestErr := api.GetOperatorRequest(ctx, id)
	err = decodeClientResponse(response, requestErr, &wire)
	return requestFromWire(wire), err
}

func (c *Client) Decide(ctx context.Context, id string, action operatorv1.Action, decision operatorv1.Decision) (operatorv1.Request, error) {
	api, err := c.api()
	if err != nil {
		return operatorv1.Request{}, err
	}
	wireDecision := decisionToWire(decision)
	var wire operatorwire.BrokerRequest
	response, requestErr := api.DecideOperatorRequest(ctx, id, operatorwire.Action(action), wireDecision)
	err = decodeClientResponse(response, requestErr, &wire)
	return requestFromWire(wire), err
}

func (c *Client) Watch(ctx context.Context, cursor string) (operatorv1.EventStream, error) {
	api, err := c.api()
	if err != nil {
		return nil, err
	}
	params := operatorwire.StreamOperatorEventsParams{Cursor: optional.NonZero(cursor)}
	response, err := api.StreamOperatorEvents(ctx, &params, func(_ context.Context, request *http.Request) error {
		request.Header.Set("Accept", "text/event-stream")
		return nil
	})
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		err := decodeAPIError(response)
		_ = response.Body.Close()
		return nil, err
	}
	if !hasMediaType(response.Header.Get("Content-Type"), "text/event-stream") {
		_ = response.Body.Close()
		return nil, errors.New("operator event response has invalid content type")
	}
	return &eventStream{body: response.Body, scanner: newSSEScanner(response.Body)}, nil
}

func (c *Client) api() (operatorwire.ClientInterface, error) {
	base, err := parseBaseURL(c.BaseURL)
	if err != nil {
		return nil, err
	}
	return operatorwire.NewClient(base.String(), operatorwire.WithHTTPClient(c.httpClient()),
		operatorwire.WithRequestEditorFn(func(_ context.Context, request *http.Request) error {
			if c.Token != "" {
				request.Header.Set("Authorization", "Bearer "+c.Token)
			}
			return nil
		}))
}

func targetQueryEditor(fields map[string][]string) operatorwire.RequestEditorFn {
	return func(_ context.Context, request *http.Request) error {
		values := request.URL.Query()
		for key, list := range fields {
			for _, value := range list {
				values.Add("target."+key, value)
			}
		}
		request.URL.RawQuery = values.Encode()
		return nil
	}
}

func decodeClientResponse(response *http.Response, err error, target any) error {
	if err != nil {
		return err
	}
	if response == nil {
		return errors.New("operator source returned no response")
	}
	defer func() { _ = response.Body.Close() }()
	return decodeJSONResponse(response, target)
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
		event, err := s.receiveNext()
		resultc <- result{event, err}
	}()
	select {
	case <-ctx.Done():
		_ = s.body.Close()
		return operatorv1.Event{}, ctx.Err()
	case result := <-resultc:
		if result.err == nil && result.event.Cursor == "" {
			result.err = errors.New("operator event cursor is required")
		}
		return result.event, result.err
	}
}

func (s *eventStream) receiveNext() (operatorv1.Event, error) {
	for s.scanner.Scan() {
		line := s.scanner.Text()
		if strings.HasPrefix(line, ":") {
			continue
		}
		if strings.HasPrefix(line, "data:") {
			var wire operatorwire.BrokerEvent
			err := strictjson.Decode([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))), &wire, false)
			return eventFromWire(wire), err
		}
	}
	return operatorv1.Event{}, s.scanner.Err()
}

func (s *eventStream) Close() error { return s.body.Close() }

func newSSEScanner(reader io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4*1024), 128*1024)
	return scanner
}

func decodeJSONResponse(response *http.Response, target any) error {
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return decodeAPIError(response)
	}
	if !hasMediaType(response.Header.Get("Content-Type"), "application/json") {
		return errors.New("operator response has invalid content type")
	}
	return decodeBounded(response.Body, target)
}

func hasMediaType(value, expected string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == expected
}

func parseBaseURL(value string) (*url.URL, error) {
	base, err := url.Parse(value)
	if err != nil || !validBaseURL(base) {
		return nil, errors.New("operator base URL is invalid")
	}
	return base, nil
}

func validBaseURL(base *url.URL) bool {
	return (base.Scheme == "http" || base.Scheme == "https") && base.Host != "" && base.User == nil && base.RawQuery == "" && base.Fragment == ""
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func decodeAPIError(response *http.Response) error {
	if !hasMediaType(response.Header.Get("Content-Type"), "application/json") {
		return &Error{Status: response.StatusCode, Code: "internal_error", Message: "invalid operator error response"}
	}
	var envelope operatorwire.ErrorEnvelope
	if err := decodeBounded(response.Body, &envelope); err != nil {
		return &Error{Status: response.StatusCode, Code: "internal_error", Message: "invalid operator error response"}
	}
	retry, _ := strconv.Atoi(response.Header.Get("Retry-After"))
	var current *operatorv1.Request
	if envelope.Error.Current != nil {
		value := requestFromWire(*envelope.Error.Current)
		current = &value
	}
	return &Error{Status: response.StatusCode, Code: string(envelope.Error.Code), Message: envelope.Error.Message,
		CorrelationID: envelope.Error.CorrelationId, Current: current, RetryAfter: time.Duration(retry) * time.Second}
}

func decisionToWire(input operatorv1.Decision) operatorwire.Decision {
	result := operatorwire.Decision{ExpectedRevision: int(input.ExpectedRevision), IdempotencyKey: input.IdempotencyKey,
		OnBehalfOf: optional.NonZero(input.OnBehalfOf)}
	if input.Constraints != nil {
		result.Constraints = &operatorwire.Constraints{}
		if input.Constraints.DurationSeconds != 0 {
			value := int(input.Constraints.DurationSeconds)
			result.Constraints.DurationSeconds = &value
		}
		if input.Constraints.MaxUses.Specified {
			result.Constraints.MaxUses = operatorv1wire.UseLimitToWire(input.Constraints.MaxUses.Limit)
		}
	}
	return result
}

func pageFromWire(input operatorwire.RequestPage) operatorv1.Page {
	result := operatorv1.Page{Requests: make([]operatorv1.Request, 0, len(input.Requests))}
	if input.NextCursor != nil {
		result.NextCursor = *input.NextCursor
	}
	if input.EventCursor != nil {
		result.EventCursor = *input.EventCursor
	}
	for _, request := range input.Requests {
		result.Requests = append(result.Requests, requestFromWire(request))
	}
	return result
}

func requestFromWire(input operatorwire.BrokerRequest) operatorv1.Request {
	facts := []operatorv1.Fact{}
	if input.Presentation.Facts != nil {
		for _, fact := range *input.Presentation.Facts {
			facts = append(facts, operatorv1.Fact{Label: fact.Label, Value: fact.Value})
		}
	}
	result := operatorv1.Request{ID: input.Id, Revision: int64(input.Revision), Requester: input.Requester, Operation: input.Operation,
		Status: grants.Status(input.Status), RequestedAt: input.RequestedAt, PendingExpiresAt: input.PendingExpiresAt,
		ActiveExpiresAt: input.ActiveExpiresAt, RequestedDurationSeconds: int64(input.RequestedDurationSeconds),
		RequestedMaxUses: operatorv1wire.UseLimitFromWire(input.RequestedMaxUses), GrantedMaxUses: operatorv1wire.UseLimitFromWire(input.GrantedMaxUses),
		UsedCount: input.UsedCount, DecidedAt: input.DecidedAt,
		Presentation:   operatorv1.Presentation{Risk: string(input.Presentation.Risk), Title: input.Presentation.Title, Facts: facts},
		AllowedActions: make([]operatorv1.Action, 0, len(input.AllowedActions))}
	result.RequestReason = optional.Value(input.RequestReason)
	result.DecidedBy = optional.Value(input.DecidedBy)
	result.DecidedOnBehalfOf = optional.Value(input.DecidedOnBehalfOf)
	result.Presentation.Summary = optional.Value(input.Presentation.Summary)
	result.PresentationUnavailable = boolValue(input.PresentationUnavailable)
	for _, action := range input.AllowedActions {
		result.AllowedActions = append(result.AllowedActions, operatorv1.Action(action))
	}
	if input.ApprovalBounds != nil {
		result.ApprovalBounds = &operatorv1.ApprovalBounds{MaxDurationSeconds: int64(input.ApprovalBounds.MaxDurationSeconds), MaxUses: operatorv1wire.UseLimitFromWire(input.ApprovalBounds.MaxUses)}
	}
	return result
}

func eventFromWire(input operatorwire.BrokerEvent) operatorv1.Event {
	return operatorv1.Event{Cursor: input.Cursor, Kind: string(input.Kind), RequestID: input.RequestId, Revision: int64(input.Revision),
		Status: grants.Status(input.Status), OccurredAt: input.OccurredAt, UsedCount: input.UsedCount}
}

func boolValue(value *bool) bool {
	return value != nil && *value
}

func decodeBounded(reader io.Reader, target any) error {
	data, err := httpx.ReadLimited(reader, maxResponseBytes)
	if err != nil {
		return err
	}
	if err := strictjson.Decode(data, target, false); err != nil {
		return fmt.Errorf("decode operator response: %w", err)
	}
	return nil
}

var _ operatorv1.Source = (*Client)(nil)
