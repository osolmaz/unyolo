// Package credentialauth validates Hugging Face provider credentials without
// exposing their secret value.
package credentialauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	TokenFormURL   = "https://huggingface.co/settings/tokens/new?tokenType=fineGrained"
	maxTokenBytes  = 64 * 1024
	maxWhoamiBytes = 1 << 20
)

// Scope is one fine-grained Hugging Face permission scope.
type Scope struct {
	EntityType  string   `json:"entity_type"`
	EntityName  string   `json:"entity_name,omitempty"`
	Permissions []string `json:"permissions"`
}

// Inspection is the secret-free result of validating a credential.
type Inspection struct {
	Version           int      `json:"version"`
	Account           string   `json:"account"`
	Organizations     []string `json:"organizations"`
	TokenType         string   `json:"token_type"`
	GlobalPermissions []string `json:"global_permissions"`
	Scopes            []Scope  `json:"scopes"`
	CanReadGatedRepos bool     `json:"can_read_gated_repos"`
	FingerprintSHA256 string   `json:"fingerprint_sha256"`
	CapabilityDigest  string   `json:"capability_digest"`
	VerifiedAt        string   `json:"verified_at"`
}

// VerifiedTime parses the canonical inspection timestamp.
func (i Inspection) VerifiedTime() (time.Time, error) {
	value, err := time.Parse(time.RFC3339, i.VerifiedAt)
	if err != nil {
		return time.Time{}, errors.New("Hugging Face credential verification time is invalid")
	}
	return value.UTC(), nil
}

// Inspector verifies candidate tokens against a Hugging Face Hub origin.
type Inspector struct {
	BaseURL string
	Client  *http.Client
	Now     func() time.Time
}

type whoamiResponse struct {
	Name string `json:"name"`
	Orgs []struct {
		Name string `json:"name"`
	} `json:"orgs"`
	Auth struct {
		Type        string `json:"type"`
		AccessToken struct {
			Role        string `json:"role"`
			FineGrained *struct {
				Global            []any `json:"global"`
				CanReadGatedRepos bool  `json:"canReadGatedRepos"`
				Scoped            []struct {
					Entity struct {
						Type string `json:"type"`
						Name string `json:"name"`
					} `json:"entity"`
					Permissions []any `json:"permissions"`
				} `json:"scoped"`
			} `json:"fineGrained"`
		} `json:"accessToken"`
	} `json:"auth"`
}

// Inspect verifies token and returns only non-secret metadata.
func (i Inspector) Inspect(ctx context.Context, token string) (Inspection, error) {
	token, err := NormalizeToken(token)
	if err != nil {
		return Inspection{}, err
	}
	base, err := validateBaseURL(i.BaseURL)
	if err != nil {
		return Inspection{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/whoami-v2", nil)
	if err != nil {
		return Inspection{}, errors.New("build Hugging Face credential inspection request")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	client := i.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return Inspection{}, errors.New("Hugging Face credential inspection is unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Inspection{}, credentialResponseError(response.StatusCode)
	}
	var payload whoamiResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxWhoamiBytes+1))
	if err := decoder.Decode(&payload); err != nil {
		return Inspection{}, errors.New("Hugging Face returned an invalid credential response")
	}
	if err := ensureResponseEnded(decoder); err != nil {
		return Inspection{}, err
	}
	return inspectionFromResponse(token, payload, i.now())
}

// NormalizeToken validates the bounded token input and strips surrounding whitespace.
func NormalizeToken(token string) (string, error) {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return "", errors.New("Hugging Face token is required")
	}
	if len(trimmed) > maxTokenBytes {
		return "", errors.New("Hugging Face token exceeds the size limit")
	}
	if !strings.HasPrefix(trimmed, "hf_") || strings.ContainsAny(trimmed, "\r\n\t ") {
		return "", errors.New("Hugging Face token has an invalid format")
	}
	return trimmed, nil
}

func validateBaseURL(raw string) (string, error) {
	if raw == "" {
		raw = "https://huggingface.co"
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("invalid Hugging Face inspection origin")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func credentialResponseError(status int) error {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return errors.New("Hugging Face did not accept this token")
	case http.StatusTooManyRequests:
		return errors.New("Hugging Face credential inspection was rate limited")
	default:
		return fmt.Errorf("Hugging Face credential inspection returned HTTP %d", status)
	}
}

func ensureResponseEnded(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return errors.New("Hugging Face returned an oversized or invalid credential response")
}

func inspectionFromResponse(token string, payload whoamiResponse, now time.Time) (Inspection, error) {
	if strings.TrimSpace(payload.Name) == "" {
		return Inspection{}, errors.New("Hugging Face credential response omitted the account name")
	}
	access := payload.Auth.AccessToken
	if access.Role != "fineGrained" || access.FineGrained == nil {
		return Inspection{}, errors.New("HF Broker requires a dedicated fine-grained Hugging Face token")
	}
	organizations := make([]string, 0, len(payload.Orgs))
	for _, organization := range payload.Orgs {
		if name := strings.TrimSpace(organization.Name); name != "" {
			organizations = append(organizations, name)
		}
	}
	organizations = sortedUnique(organizations)
	global := stringValues(access.FineGrained.Global)
	scopes := normalizedScopes(access.FineGrained.Scoped)
	fingerprint := sha256.Sum256([]byte(token))
	capabilities, err := json.Marshal(struct {
		Global []string `json:"global"`
		Scopes []Scope  `json:"scopes"`
		Gated  bool     `json:"gated"`
	}{global, scopes, access.FineGrained.CanReadGatedRepos})
	if err != nil {
		return Inspection{}, errors.New("encode Hugging Face credential capabilities")
	}
	digest := sha256.Sum256(capabilities)
	return Inspection{
		Version: 1, Account: strings.TrimSpace(payload.Name), Organizations: organizations,
		TokenType: "fineGrained", GlobalPermissions: global, Scopes: scopes,
		CanReadGatedRepos: access.FineGrained.CanReadGatedRepos,
		FingerprintSHA256: hex.EncodeToString(fingerprint[:]), CapabilityDigest: hex.EncodeToString(digest[:]),
		VerifiedAt: now.UTC().Format(time.RFC3339),
	}, nil
}

func normalizedScopes(values []struct {
	Entity struct {
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"entity"`
	Permissions []any `json:"permissions"`
}) []Scope {
	result := make([]Scope, 0, len(values))
	for _, value := range values {
		typeName := strings.TrimSpace(value.Entity.Type)
		permissions := stringValues(value.Permissions)
		if typeName == "" || len(permissions) == 0 {
			continue
		}
		result = append(result, Scope{EntityType: typeName, EntityName: strings.TrimSpace(value.Entity.Name), Permissions: permissions})
	}
	slices.SortFunc(result, func(a, b Scope) int {
		if value := strings.Compare(a.EntityType, b.EntityType); value != 0 {
			return value
		}
		return strings.Compare(a.EntityName, b.EntityName)
	})
	return result
}

func stringValues(values []any) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if ok && strings.TrimSpace(text) == text && text != "" {
			result = append(result, text)
		}
	}
	return sortedUnique(result)
}

func sortedUnique(values []string) []string {
	slices.Sort(values)
	return slices.Compact(values)
}

func (i Inspector) now() time.Time {
	if i.Now != nil {
		return i.Now()
	}
	return time.Now()
}
