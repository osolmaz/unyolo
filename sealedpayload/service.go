// Package sealedpayload owns the provider-neutral upload and expiry lifecycle
// for encrypted, single-use operation inputs.
package sealedpayload

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/brokerkit/capability"
	"github.com/osolmaz/brokerkit/sealedstore"
)

const (
	MaxPayloadBytes      = 1 << 20
	defaultSweepInterval = time.Minute
)

// Options configures the shared sealed-payload boundary.
type Options struct {
	Store         *sealedstore.Store
	Descriptor    func(string) (capability.Descriptor, bool)
	Authenticate  func(http.ResponseWriter, *http.Request) (string, bool)
	WriteFailure  func(http.ResponseWriter, int, string, string)
	Now           func() time.Time
	SweepInterval time.Duration
}

// Service validates uploads and expires encrypted payloads.
type Service struct {
	options Options
	workers sync.WaitGroup
}

// New validates a sealed-payload service.
func New(options Options) (*Service, error) {
	if options.Store == nil || options.Descriptor == nil || options.Authenticate == nil || options.WriteFailure == nil {
		return nil, errors.New("sealed payload options are incomplete")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.SweepInterval <= 0 {
		options.SweepInterval = defaultSweepInterval
	}
	return &Service{options: options}, nil
}

// Start sweeps expired payloads until ctx is canceled.
func (s *Service) Start(ctx context.Context) {
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		_, _ = s.options.Store.SweepExpired(s.options.Now())
		ticker := time.NewTicker(s.options.SweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				_, _ = s.options.Store.SweepExpired(now)
			}
		}
	}()
}

// Wait waits for the sweeper after its context is canceled.
func (s *Service) Wait() { s.workers.Wait() }

// Upload authenticates and stores one bounded sealed payload.
//
//nolint:cyclop // Boundary checks remain explicit and fail closed.
func (s *Service) Upload(c echo.Context) error {
	request := c.Request()
	client, ok := s.options.Authenticate(c.Response(), request)
	if !ok {
		return nil
	}
	operation := strings.TrimSpace(request.Header.Get("X-Broker-Operation"))
	requestKey := strings.TrimSpace(request.Header.Get("X-Broker-Idempotency-Key"))
	descriptor, found := s.options.Descriptor(operation)
	if !found || !descriptor.Sealed || !descriptor.AgentFacing || descriptor.AuthorizationMode != capability.ModeExecution {
		s.options.WriteFailure(c.Response(), http.StatusBadRequest, "sealed_purpose_invalid", "A sealed operation is required")
		return nil
	}
	if !ValidRequestKey(requestKey) || !ValidRequestBody(request) {
		s.options.WriteFailure(c.Response(), http.StatusBadRequest, "sealed_payload_invalid", "Sealed payload must be bounded binary content")
		return nil
	}
	payload, err := io.ReadAll(io.LimitReader(request.Body, MaxPayloadBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > MaxPayloadBytes {
		s.options.WriteFailure(c.Response(), http.StatusBadRequest, "sealed_payload_invalid", "Sealed payload must be bounded binary content")
		return nil //nolint:nilerr // The bounded redacted failure response is already committed.
	}
	expires := s.options.Now().Add(time.Duration(descriptor.RequestTTLSeconds+descriptor.ApprovalTTLSeconds+300) * time.Second)
	reference, err := s.options.Store.PutForRequest(client, operation, requestKey, payload, expires)
	for index := range payload {
		payload[index] = 0
	}
	if err != nil {
		s.options.WriteFailure(c.Response(), http.StatusInternalServerError, "sealed_payload_unavailable", "Could not seal operation payload")
		return nil //nolint:nilerr // The redacted failure response is already committed.
	}
	c.Response().Header().Set("Content-Type", "application/json")
	c.Response().WriteHeader(http.StatusCreated)
	return json.NewEncoder(c.Response()).Encode(reference)
}

// ValidRequestKey validates the binding key carried beside a sealed upload.
func ValidRequestKey(value string) bool {
	return value != "" && len(value) <= 128 && !strings.ContainsAny(value, " \t\r\n")
}

// ValidRequestBody validates the bounded binary HTTP envelope.
func ValidRequestBody(request *http.Request) bool {
	return request.Header.Get("Content-Type") == "application/octet-stream" && request.ContentLength > 0 &&
		request.ContentLength <= MaxPayloadBytes
}
