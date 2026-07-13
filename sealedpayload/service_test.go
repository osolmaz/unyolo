package sealedpayload

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/brokerkit/capability"
	"github.com/osolmaz/brokerkit/sealedstore"
)

func TestUploadBindsPayloadToDescriptorAndRequester(t *testing.T) {
	store, err := sealedstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	descriptor := capability.Descriptor{Name: "secret.set", AuthorizationMode: capability.ModeExecution, AgentFacing: true,
		Sealed: true, RequestTTLSeconds: 60, ApprovalTTLSeconds: 60}
	service, err := New(Options{
		Store:        store,
		Descriptor:   func(name string) (capability.Descriptor, bool) { return descriptor, name == descriptor.Name },
		Authenticate: func(http.ResponseWriter, *http.Request) (string, bool) { return "agent", true },
		WriteFailure: func(w http.ResponseWriter, status int, _, _ string) { w.WriteHeader(status) },
		Now:          time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/agent/v1/sealed-payloads", bytes.NewBufferString(`{"value":"secret"}`))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Broker-Operation", descriptor.Name)
	request.Header.Set("X-Broker-Idempotency-Key", "request-1")
	response := httptest.NewRecorder()
	ctx := echo.New().NewContext(request, response)
	if err := service.Upload(ctx); err != nil || response.Code != http.StatusCreated {
		t.Fatalf("upload = %d, %v", response.Code, err)
	}
}

func TestUploadRejectsUnsealedPurpose(t *testing.T) {
	store, err := sealedstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(Options{
		Store: store,
		Descriptor: func(string) (capability.Descriptor, bool) {
			return capability.Descriptor{Name: "repo.read", AuthorizationMode: capability.ModeWindow, AgentFacing: true}, true
		},
		Authenticate: func(http.ResponseWriter, *http.Request) (string, bool) { return "agent", true },
		WriteFailure: func(w http.ResponseWriter, status int, _, _ string) { w.WriteHeader(status) },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString("x"))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Broker-Operation", "repo.read")
	request.Header.Set("X-Broker-Idempotency-Key", "request-1")
	response := httptest.NewRecorder()
	if err := service.Upload(echo.New().NewContext(request, response)); err != nil || response.Code != http.StatusBadRequest {
		t.Fatalf("upload = %d, %v", response.Code, err)
	}
}

func TestUploadRejectsInvalidBoundaries(t *testing.T) {
	descriptor := capability.Descriptor{Name: "secret.set", AuthorizationMode: capability.ModeExecution, AgentFacing: true,
		Sealed: true, RequestTTLSeconds: 60, ApprovalTTLSeconds: 60}
	tests := []struct {
		name          string
		authenticated bool
		contentType   string
		requestKey    string
		body          []byte
		now           func() time.Time
		wantStatus    int
	}{
		{name: "unauthenticated", contentType: "application/octet-stream", requestKey: "request", body: []byte("x"), wantStatus: http.StatusOK},
		{name: "request key", authenticated: true, contentType: "application/octet-stream", body: []byte("x"), wantStatus: http.StatusBadRequest},
		{name: "content type", authenticated: true, contentType: "application/json", requestKey: "request", body: []byte("x"), wantStatus: http.StatusBadRequest},
		{name: "too large", authenticated: true, contentType: "application/octet-stream", requestKey: "request", body: bytes.Repeat([]byte("x"), MaxPayloadBytes+1), wantStatus: http.StatusBadRequest},
		{name: "expired", authenticated: true, contentType: "application/octet-stream", requestKey: "request", body: []byte("x"), now: func() time.Time { return time.Unix(1, 0) }, wantStatus: http.StatusInternalServerError},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, err := sealedstore.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			service, err := New(Options{
				Store: store, Descriptor: func(string) (capability.Descriptor, bool) { return descriptor, true },
				Authenticate: func(http.ResponseWriter, *http.Request) (string, bool) { return "agent", test.authenticated },
				WriteFailure: func(w http.ResponseWriter, status int, _, _ string) { w.WriteHeader(status) }, Now: test.now,
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			request.Header.Set("X-Broker-Operation", descriptor.Name)
			request.Header.Set("X-Broker-Idempotency-Key", test.requestKey)
			response := httptest.NewRecorder()
			if err := service.Upload(echo.New().NewContext(request, response)); err != nil || response.Code != test.wantStatus {
				t.Fatalf("upload = %d, %v", response.Code, err)
			}
		})
	}
}

func TestServiceLifecycleAndOptionValidation(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("incomplete service was accepted")
	}
	store, err := sealedstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(Options{Store: store,
		Descriptor:   func(string) (capability.Descriptor, bool) { return capability.Descriptor{}, false },
		Authenticate: func(http.ResponseWriter, *http.Request) (string, bool) { return "", false },
		WriteFailure: func(http.ResponseWriter, int, string, string) {}, SweepInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	service.Start(ctx)
	cancel()
	service.Wait()
}
