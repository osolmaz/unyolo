package upstreamdrift

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientFetchesBoundedOfficialDocument(t *testing.T) {
	document := `{"paths":{"/api/models":{"get":{"operationId":"listModels","responses":{"200":{}}}}}}`
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Accept") != "application/json" || request.Header.Get("User-Agent") != userAgent {
			t.Fatalf("unexpected headers: %v", request.Header)
		}
		_, _ = io.WriteString(writer, document)
	}))
	defer server.Close()

	client := NewClient()
	client.url = server.URL
	client.now = func() time.Time { return time.Date(2026, 7, 17, 1, 2, 3, 0, time.UTC) }
	data, source, err := client.FetchCurrent(context.Background())
	if err != nil || string(data) != document || source.URL != SourceURL || source.SHA256 == "" || source.RetrievedAt.IsZero() {
		t.Fatalf("FetchCurrent() = %q, %+v, %v", data, source, err)
	}
}

func TestClientRejectsFailuresAndOversizedDocuments(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"status": func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusBadGateway) },
		"empty":  func(http.ResponseWriter, *http.Request) {},
		"large": func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = writer.Write(bytes.Repeat([]byte("x"), maxDocumentBytes+1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			client := NewClient()
			client.url = server.URL
			if _, _, err := client.FetchCurrent(context.Background()); err == nil {
				t.Fatal("failure accepted")
			}
		})
	}
	if _, _, err := (*Client)(nil).FetchCurrent(context.Background()); err == nil {
		t.Fatal("nil client accepted")
	}
}

func TestClientRejectsRedirectsInvalidURLsAndReadFailures(t *testing.T) {
	redirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "/other", http.StatusFound)
	}))
	defer redirect.Close()
	client := NewClient()
	client.url = redirect.URL
	if _, _, err := client.FetchCurrent(context.Background()); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("redirect error = %v", err)
	}

	client = NewClient()
	client.url = "://invalid"
	if _, _, err := client.FetchCurrent(context.Background()); err == nil {
		t.Fatal("invalid URL accepted")
	}

	client = NewClient()
	client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: failingBody{}, Header: make(http.Header)}, nil
	})
	if _, _, err := client.FetchCurrent(context.Background()); err == nil || !strings.Contains(err.Error(), "read official") {
		t.Fatalf("read error = %v", err)
	}
}

func TestAnalyzeAndWriteMarkdown(t *testing.T) {
	pinned := []byte(`{"paths":{"/api/models":{"get":{"operationId":"listModels","responses":{"200":{}}}}}}`)
	current := []byte(`{"paths":{"/api/models":{"get":{"operationId":"listModels","responses":{"200":{"content":{"application/json":{"schema":{"type":"array"}}}}}}}}}`)
	report, err := Analyze(pinned, current, Source{URL: SourceURL, SHA256: "abc", RetrievedAt: time.Now()})
	if err != nil || !report.HasDrift() {
		t.Fatalf("Analyze() = %+v, %v", report, err)
	}
	var output strings.Builder
	if err := WriteMarkdown(&output, report); err != nil || !strings.Contains(output.String(), "Structural drift detected") || !strings.Contains(output.String(), "`schema` changed") {
		t.Fatalf("WriteMarkdown() = %q, %v", output.String(), err)
	}
	if err := WriteMarkdown(nil, report); err == nil {
		t.Fatal("nil writer accepted")
	}
	output.Reset()
	if err := WriteMarkdown(&output, Report{Source: report.Source}); err != nil || !strings.Contains(output.String(), "No snapshot refresh is required") {
		t.Fatalf("clean report = %q, %v", output.String(), err)
	}
	changes := make([]Change, maxReportedChanges+5)
	for index := range changes {
		changes[index] = Change{Category: "operation", Kind: "added", Key: "unsafe`\nkey"}
	}
	output.Reset()
	if err := WriteMarkdown(&output, Report{Source: report.Source, Changes: changes}); err != nil || !strings.Contains(output.String(), "5 additional changes omitted") || strings.Contains(output.String(), "unsafe`") {
		t.Fatalf("bounded report = %q, %v", output.String(), err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (failingBody) Close() error             { return nil }
