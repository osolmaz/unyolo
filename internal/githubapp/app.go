// Package githubapp mints short-lived GitHub App installation tokens.
package githubapp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	jwtLifetime        = 9 * time.Minute
	jwtIssuedAtSkew    = time.Minute
	maxGitHubBodyBytes = 1 << 20
)

// Token is one short-lived GitHub App installation token.
type Token struct {
	Value          string
	InstallationID int64
}

// Source signs GitHub App JWTs and mints installation tokens.
type Source struct {
	appID      string
	privateKey *rsa.PrivateKey
	apiBaseURL *url.URL
	httpClient *http.Client
	now        func() time.Time
	mu         sync.Mutex
}

// Config contains the files and clients needed to mint installation tokens.
type Config struct {
	AppID         string
	PrivateKeyPEM []byte
	APIBaseURL    *url.URL
	HTTPClient    *http.Client
	Now           func() time.Time
}

// New creates a GitHub App token source.
func New(cfg Config) (*Source, error) {
	appID := strings.TrimSpace(cfg.AppID)
	if appID == "" {
		return nil, errors.New("github app id is required")
	}
	key, err := parsePrivateKey(cfg.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	baseURL := cfg.APIBaseURL
	if baseURL == nil {
		baseURL, err = url.Parse("https://api.github.com")
		if err != nil {
			return nil, err
		}
	}
	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Source{appID: appID, privateKey: key, apiBaseURL: baseURL, httpClient: client, now: now}, nil
}

// InstallationTokenForRepo resolves the app installation for one repository and mints a token.
func (s *Source) InstallationTokenForRepo(ctx context.Context, owner string, repo string) (Token, error) {
	installationID, err := s.ResolveRepoInstallation(ctx, owner, repo)
	if err != nil {
		return Token{}, err
	}
	return s.InstallationToken(ctx, installationID)
}

// ResolveRepoInstallation resolves the GitHub App installation id for one repository.
func (s *Source) ResolveRepoInstallation(ctx context.Context, owner string, repo string) (int64, error) {
	if strings.TrimSpace(owner) == "" || strings.TrimSpace(repo) == "" {
		return 0, errors.New("repo owner and name are required")
	}
	var payload struct {
		ID int64 `json:"id"`
	}
	if err := s.doAppJSON(ctx, http.MethodGet, []string{"repos", owner, repo, "installation"}, nil, &payload); err != nil {
		return 0, err
	}
	if payload.ID <= 0 {
		return 0, errors.New("github app installation response did not include id")
	}
	return payload.ID, nil
}

// InstallationToken mints a token for one installation id.
func (s *Source) InstallationToken(ctx context.Context, installationID int64) (Token, error) {
	if installationID <= 0 {
		return Token{}, errors.New("installation id must be positive")
	}
	var payload struct {
		Token string `json:"token"`
	}
	if err := s.doAppJSON(ctx, http.MethodPost, []string{"app", "installations", strconv.FormatInt(installationID, 10), "access_tokens"}, []byte(`{}`), &payload); err != nil {
		return Token{}, err
	}
	value := strings.TrimSpace(payload.Token)
	if value == "" {
		return Token{}, errors.New("github app access token response did not include token")
	}
	return Token{Value: value, InstallationID: installationID}, nil
}

// Installations lists installations visible to the app.
func (s *Source) Installations(ctx context.Context) ([]int64, error) {
	var payload []struct {
		ID int64 `json:"id"`
	}
	if err := s.doAppJSON(ctx, http.MethodGet, []string{"app", "installations"}, nil, &payload); err != nil {
		return nil, err
	}
	ids := make([]int64, 0, len(payload))
	for _, item := range payload {
		if item.ID > 0 {
			ids = append(ids, item.ID)
		}
	}
	return ids, nil
}

func (s *Source) doAppJSON(ctx context.Context, method string, path []string, body []byte, out any) error {
	request, err := s.newAppRequest(ctx, method, path, body)
	if err != nil {
		return err
	}
	response, err := s.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("github app request failed: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	return decodeAppResponse(response, out)
}

func (s *Source) newAppRequest(ctx context.Context, method string, path []string, body []byte) (*http.Request, error) {
	jwt, err := s.JWT()
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, method, s.apiBaseURL.JoinPath(path...).String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create github app request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+jwt)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return request, nil
}

func decodeAppResponse(response *http.Response, out any) error {
	data, err := io.ReadAll(io.LimitReader(response.Body, maxGitHubBodyBytes+1))
	if err != nil {
		return fmt.Errorf("read github app response: %w", err)
	}
	if len(data) > maxGitHubBodyBytes {
		return errors.New("github app response is too large")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("github app request failed with status %d", response.StatusCode)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode github app response: %w", err)
	}
	return nil
}

// JWT signs a GitHub App JWT with RS256.
func (s *Source) JWT() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	payload := map[string]any{
		"iat": now.Add(-jwtIssuedAtSkew).Unix(),
		"exp": now.Add(jwtLifetime).Unix(),
		"iss": s.appID,
	}
	signingInput, err := jwtSigningInput(header, payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign github app jwt: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func jwtSigningInput(header any, payload any) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON), nil
}

func parsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("github app private key must be PEM encoded")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse github app private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("github app private key must be RSA")
	}
	return key, nil
}
