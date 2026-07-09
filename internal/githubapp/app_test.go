package githubapp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestJWTIncludesGitHubAppClaims(t *testing.T) {
	t.Parallel()
	source := newTestSource(t, nil)
	jwt, err := source.JWT()
	if err != nil {
		t.Fatalf("JWT() error = %v", err)
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt parts = %d, want 3", len(parts))
	}
	var header map[string]string
	decodeJWTPart(t, parts[0], &header)
	if header["alg"] != "RS256" || header["typ"] != "JWT" {
		t.Fatalf("jwt header = %+v", header)
	}
	var payload struct {
		Iss string `json:"iss"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	decodeJWTPart(t, parts[1], &payload)
	if payload.Iss != "12345" {
		t.Fatalf("iss = %q, want app id", payload.Iss)
	}
	if payload.Exp-payload.Iat != int64(jwtLifetime+jwtIssuedAtSkew)/int64(time.Second) {
		t.Fatalf("exp-iat = %d", payload.Exp-payload.Iat)
	}
	if parts[2] == "" {
		t.Fatal("jwt signature is empty")
	}
}

func TestInstallationTokenForRepoResolvesAndMints(t *testing.T) {
	t.Parallel()
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Fatalf("authorization header = %q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/repos/dutifuldev/gh-broker/installation":
			writeJSON(w, `{"id":42}`)
		case "/app/installations/42/access_tokens":
			if r.Method != http.MethodPost {
				t.Fatalf("mint method = %s, want POST", r.Method)
			}
			writeJSON(w, `{"token":"ghs_installation_token"}`)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	source := newTestSource(t, server)
	token, err := source.InstallationTokenForRepo(context.Background(), "dutifuldev", "gh-broker")
	if err != nil {
		t.Fatalf("InstallationTokenForRepo() error = %v", err)
	}
	if token.Value != "ghs_installation_token" || token.InstallationID != 42 {
		t.Fatalf("token = %+v", token)
	}
	if strings.Join(paths, ",") != "/repos/dutifuldev/gh-broker/installation,/app/installations/42/access_tokens" {
		t.Fatalf("paths = %v", paths)
	}
}

func TestInstallationsFiltersInvalidIDs(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app/installations" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		writeJSON(w, `[{"id":42},{"id":0},{"id":77}]`)
	}))
	t.Cleanup(server.Close)
	source := newTestSource(t, server)
	ids, err := source.Installations(context.Background())
	if err != nil {
		t.Fatalf("Installations() error = %v", err)
	}
	if got := strings.Join([]string{strconv.FormatInt(ids[0], 10), strconv.FormatInt(ids[1], 10)}, ","); got != "42,77" {
		t.Fatalf("ids = %v", ids)
	}
}

func TestGitHubAppResponseErrors(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		path string
		body string
		run  func(*Source) error
	}{
		"repo installation missing id": {
			path: "/repos/dutifuldev/gh-broker/installation",
			body: `{}`,
			run: func(source *Source) error {
				_, err := source.ResolveRepoInstallation(context.Background(), "dutifuldev", "gh-broker")
				return err
			},
		},
		"installation token missing token": {
			path: "/app/installations/42/access_tokens",
			body: `{}`,
			run: func(source *Source) error {
				_, err := source.InstallationToken(context.Background(), 42)
				return err
			},
		},
		"non success status": {
			path: "/app/installations",
			body: `status-failed`,
			run: func(source *Source) error {
				_, err := source.Installations(context.Background())
				return err
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.path {
					t.Fatalf("path = %s, want %s", r.URL.Path, tc.path)
				}
				if tc.body == "status-failed" {
					http.Error(w, "failed", http.StatusForbidden)
					return
				}
				writeJSON(w, tc.body)
			}))
			t.Cleanup(server.Close)
			if err := tc.run(newTestSource(t, server)); err == nil {
				t.Fatal("error = nil, want failure")
			}
		})
	}
}

func TestRequestValidationErrors(t *testing.T) {
	t.Parallel()
	source := newTestSource(t, nil)
	if _, err := source.ResolveRepoInstallation(context.Background(), "", "repo"); err == nil {
		t.Fatal("ResolveRepoInstallation(empty owner) error = nil")
	}
	if _, err := source.InstallationToken(context.Background(), 0); err == nil {
		t.Fatal("InstallationToken(0) error = nil")
	}
}

func TestNewParsesPKCS8PrivateKey(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := New(Config{AppID: "12345", PrivateKeyPEM: pemData}); err != nil {
		t.Fatalf("New(PKCS8) error = %v", err)
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{}); err == nil {
		t.Fatal("New(empty) error = nil")
	}
	if _, err := New(Config{AppID: "123", PrivateKeyPEM: []byte("bad")}); err == nil {
		t.Fatal("New(bad key) error = nil")
	}
}

func newTestSource(t *testing.T, server *httptest.Server) *Source {
	t.Helper()
	baseURL := mustParseURL(t, "https://api.github.com")
	client := http.DefaultClient
	if server != nil {
		baseURL = mustParseURL(t, server.URL)
		client = server.Client()
	}
	source, err := New(Config{
		AppID:         "12345",
		PrivateKeyPEM: testPrivateKeyPEM(t),
		APIBaseURL:    baseURL,
		HTTPClient:    client,
		Now:           func() time.Time { return time.Date(2026, 7, 9, 17, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return source
}

func testPrivateKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func decodeJWTPart(t *testing.T, part string, out any) {
	t.Helper()
	data, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatal(err)
	}
}

func writeJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
