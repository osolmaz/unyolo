package httpapi

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/osolmaz/hf-broker/internal/audit"
	"github.com/osolmaz/hf-broker/internal/config"
	"github.com/osolmaz/hf-broker/internal/policy"
)

func TestInferenceModelsForwardsWithUpstreamCredentialAndSafeHeaders(t *testing.T) {
	var hits atomic.Int32
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/v1/models" || r.URL.RawQuery != "" {
			t.Errorf("upstream request = %s %s", r.Method, r.URL.String())
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
			t.Errorf("upstream authorization = %q", got)
		}
		if r.Header.Get("Cookie") != "" || r.Header.Get("X-Client-Header") != "" {
			t.Errorf("untrusted headers reached upstream: %v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "upstream=secret")
		w.Header().Set("X-Internal-Routing", "secret")
		_, _ = io.WriteString(w, `{"object":"list","data":[]}`)
	}))
	defer router.Close()

	broker, auditLog := newInferenceBroker(t, router.URL, 2*time.Second)
	defer broker.Close()
	req, err := http.NewRequest(http.MethodGet, broker.URL+"/v1/models", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testSecret)
	req.Header.Set("Cookie", "client=secret")
	req.Header.Set("X-Client-Header", "not-allowed")
	resp, err := broker.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != `{"object":"list","data":[]}` {
		t.Fatalf("models response = %d %q", resp.StatusCode, body)
	}
	if resp.Header.Get("Set-Cookie") != "" || resp.Header.Get("X-Internal-Routing") != "" {
		t.Fatalf("unsafe upstream headers reached client: %v", resp.Header)
	}
	if hits.Load() != 1 {
		t.Fatalf("upstream hits = %d", hits.Load())
	}
	assertInferenceAuditSafe(t, auditLog.String(), "inference.models.list", "models")
}

func TestInferenceChatPreservesTypedPayloadAndStreaming(t *testing.T) {
	requestBody := `{"model":"acme/model:fast","messages":[{"role":"user","content":"private prompt"}],"tools":[{"type":"function","function":{"name":"lookup"}}],"stream":true}`
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != requestBody {
			t.Errorf("upstream body changed: %q", body)
		}
		if r.Header.Get("Authorization") != "Bearer "+testToken || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("upstream headers = %v", r.Header)
		}
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		_, _ = io.WriteString(w, "data: {\"choices\":[]}\n\ndata: [DONE]\n\n")
	}))
	defer router.Close()

	broker, auditLog := newInferenceBroker(t, router.URL, 2*time.Second)
	defer broker.Close()
	req, err := http.NewRequest(http.MethodPost, broker.URL+"/v1/chat/completions", strings.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testSecret)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Accept", "text/event-stream")
	resp, err := broker.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "data: [DONE]") {
		t.Fatalf("chat response = %d %q", resp.StatusCode, body)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("content type = %q", resp.Header.Get("Content-Type"))
	}
	assertInferenceAuditSafe(t, auditLog.String(), "inference.chat.complete", "acme/model:fast")
	if strings.Contains(auditLog.String(), "private prompt") || strings.Contains(auditLog.String(), "lookup") {
		t.Fatalf("audit contains request content: %s", auditLog.String())
	}
}

func TestInferenceValidationFailsBeforeUpstream(t *testing.T) {
	var hits atomic.Int32
	router := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer router.Close()
	broker, _ := newInferenceBroker(t, router.URL, 2*time.Second)
	defer broker.Close()

	tests := []struct {
		name        string
		method      string
		path        string
		contentType string
		body        string
		want        int
	}{
		{name: "models method", method: http.MethodPost, path: "/v1/models", want: http.StatusMethodNotAllowed},
		{name: "models query", method: http.MethodGet, path: "/v1/models?owner=acme", want: http.StatusBadRequest},
		{name: "chat method", method: http.MethodGet, path: "/v1/chat/completions", want: http.StatusMethodNotAllowed},
		{name: "chat query", method: http.MethodPost, path: "/v1/chat/completions?debug=1", contentType: "application/json", body: `{"model":"acme/model"}`, want: http.StatusBadRequest},
		{name: "chat media type", method: http.MethodPost, path: "/v1/chat/completions", contentType: "text/plain", body: `{"model":"acme/model"}`, want: http.StatusUnsupportedMediaType},
		{name: "chat invalid json", method: http.MethodPost, path: "/v1/chat/completions", contentType: "application/json", body: `{`, want: http.StatusBadRequest},
		{name: "chat missing model", method: http.MethodPost, path: "/v1/chat/completions", contentType: "application/json", body: `{"messages":[]}`, want: http.StatusBadRequest},
		{name: "chat unsafe model", method: http.MethodPost, path: "/v1/chat/completions", contentType: "application/json", body: `{"model":"https://other.test/model"}`, want: http.StatusBadRequest},
		{name: "unknown typed route", method: http.MethodPost, path: "/v1/embeddings", contentType: "application/json", body: `{"model":"acme/model"}`, want: http.StatusNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, broker.URL+tc.path, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+testSecret)
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			resp, err := broker.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
	if hits.Load() != 0 {
		t.Fatalf("invalid requests reached upstream: %d", hits.Load())
	}
}

func TestInferenceRejectsOversizedBodyAndBoundsTimeout(t *testing.T) {
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer router.Close()
	broker, auditLog := newInferenceBroker(t, router.URL, 20*time.Millisecond)
	defer broker.Close()

	oversized := `{"model":"acme/model","input":"` + strings.Repeat("x", maxInferenceRequestBytes) + `"}`
	resp := inferenceRequestToBroker(t, broker, oversized)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp = inferenceRequestToBroker(t, broker, `{"model":"acme/model","messages":[]}`)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("timeout status = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if strings.Contains(auditLog.String(), testToken) || strings.Contains(auditLog.String(), testSecret) {
		t.Fatalf("audit leaked credentials: %s", auditLog.String())
	}
}

func TestInferenceRefusesUpstreamRedirect(t *testing.T) {
	var redirectedHits atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectedHits.Add(1)
	}))
	defer destination.Close()
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", destination.URL+"/capture")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer router.Close()
	broker, auditLog := newInferenceBroker(t, router.URL, 2*time.Second)
	defer broker.Close()

	resp := inferenceRequestToBroker(t, broker, `{"model":"acme/model","messages":[]}`)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("redirect status = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if redirectedHits.Load() != 0 {
		t.Fatalf("redirect destination was contacted %d times", redirectedHits.Load())
	}
	if strings.Contains(auditLog.String(), destination.URL) {
		t.Fatalf("audit leaked redirect destination: %s", auditLog.String())
	}
}

func TestInferenceDoesNotCommitInterruptedJSONResponse(t *testing.T) {
	router := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer router.Close()
	broker, auditLog := newInferenceBroker(t, router.URL, 2*time.Second)
	defer broker.Close()

	resp := inferenceRequestToBroker(t, broker, `{"model":"acme/model","messages":[]}`)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), "upstream_response_failed") {
		t.Fatalf("interrupted response = %d %q", resp.StatusCode, body)
	}
	if !strings.Contains(auditLog.String(), `"decision":"refused"`) || !strings.Contains(auditLog.String(), `"upstream_status":200`) {
		t.Fatalf("interrupted response audit = %s", auditLog.String())
	}
}

func TestInferenceRejectsInvalidRouterOrigin(t *testing.T) {
	scp, err := policy.Parse([]byte(emptyPolicyJSON()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(Options{
		Config: config.Config{HFToken: testToken, Clients: []config.Client{{Name: "agent", Secret: testSecret}}, StateDir: t.TempDir(), HFTimeout: time.Second},
		Scope:  scp, UpstreamBaseURL: "http://127.0.0.1:1", UpstreamRouterBaseURL: "https://user:pass@router.example.test/path?token=value",
	})
	if err == nil || strings.Contains(err.Error(), "user") || strings.Contains(err.Error(), "token") {
		t.Fatalf("invalid Router URL error = %v", err)
	}
}

func TestInferenceModelValidation(t *testing.T) {
	tests := map[string]bool{
		"acme/model":           true,
		"acme/model-v2:fast":   true,
		"acme/model.with.dots": true,
		"model":                false,
		"acme/model:fast:bad":  false,
		"acme/../model":        false,
		"acme/model--copy":     false,
		"-acme/model":          false,
		"acme/model/extra":     false,
	}
	for model, want := range tests {
		if got := validInferenceModel(model); got != want {
			t.Errorf("validInferenceModel(%q) = %v, want %v", model, got, want)
		}
	}
}

func TestReadBoundedInferenceBody(t *testing.T) {
	value, err := readBoundedInferenceBody(strings.NewReader("12345"), 5)
	if err != nil || string(value) != "12345" {
		t.Fatalf("exact body = %q, %v", value, err)
	}
	if _, err := readBoundedInferenceBody(strings.NewReader("123456"), 5); err == nil {
		t.Fatal("oversized body was accepted")
	}
	if _, err := readBoundedInferenceBody(errorReader{}, 5); err == nil {
		t.Fatal("body read error was accepted")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func TestRouterOriginValidation(t *testing.T) {
	tests := []string{
		"ftp://router.example.test",
		"https:///missing-host",
		"https://user@router.example.test",
		"https://router.example.test?debug=1",
		"https://router.example.test#fragment",
		"https://router.example.test/path",
	}
	for _, value := range tests {
		if _, err := parseRouterUpstreamBase(value); err == nil {
			t.Errorf("parseRouterUpstreamBase(%q) succeeded", value)
		}
	}
	if parsed, err := parseRouterUpstreamBase("https://router.example.test/"); err != nil || parsed.String() != "https://router.example.test" {
		t.Fatalf("root origin parsed=%v err=%v", parsed, err)
	}
}

func TestHubOriginValidationDoesNotLeakConfiguration(t *testing.T) {
	const value = "https://user:secret@hub.example.test/private?token=value"
	_, err := parseUpstreamBase(value)
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "token") {
		t.Fatalf("parseUpstreamBase() error = %v", err)
	}
}

func newInferenceBroker(t *testing.T, routerURL string, timeout time.Duration) (*httptest.Server, *bytes.Buffer) {
	t.Helper()
	scp, err := policy.Parse([]byte(emptyPolicyJSON()))
	if err != nil {
		t.Fatal(err)
	}
	var auditLog bytes.Buffer
	handler, err := New(Options{
		Config: config.Config{
			HFToken: testToken, Clients: []config.Client{{Name: "agent", Secret: testSecret}},
			StateDir: t.TempDir(), MaxPackBytes: 1024, HFTimeout: timeout,
		},
		Scope: scp, Audit: audit.New(&auditLog), UpstreamBaseURL: "http://127.0.0.1:1", UpstreamRouterBaseURL: routerURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(handler), &auditLog
}

func inferenceRequestToBroker(t *testing.T, broker *httptest.Server, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, broker.URL+"/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testSecret)
	req.Header.Set("Content-Type", "application/json")
	resp, err := broker.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func assertInferenceAuditSafe(t *testing.T, value, operation, target string) {
	t.Helper()
	if !strings.Contains(value, `"operation":"`+operation+`"`) || !strings.Contains(value, `"target":"`+target+`"`) || !strings.Contains(value, `"decision":"allowed"`) {
		t.Fatalf("audit missing safe inference fields: %s", value)
	}
	if strings.Contains(value, testToken) || strings.Contains(value, testSecret) {
		t.Fatalf("audit leaked credentials: %s", value)
	}
}
