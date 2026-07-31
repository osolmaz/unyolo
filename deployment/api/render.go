package api

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// RenderAPIVersion identifies the deterministic render exchange used at
// installation-compilation time. The exchange is stateless and does not accept
// or return credential values.
const RenderAPIVersion = "unyolo.io/setup-component-render/v1"

// RenderApprover is one approver identity accepted by every provider.
type RenderApprover struct {
	ID      string `json:"id"`
	Account string `json:"account"`
}

// RenderConnection is one nonsecret connection description supplied to a provider.
type RenderConnection struct {
	ID         string   `json:"id"`
	ClientID   string   `json:"client_id"`
	Providers  []string `json:"providers"`
	TargetKind string   `json:"target_kind"`
	Isolation  string   `json:"isolation"`
	UnixUser   string   `json:"unix_user,omitempty"`
	Home       string   `json:"home,omitempty"`
	Container  string   `json:"container,omitempty"`
	RemoteName string   `json:"remote_name,omitempty"`
}

// RenderRequest binds every nonsecret input needed for provider rendering.
type RenderRequest struct {
	APIVersion       string             `json:"api_version"`
	ComponentID      string             `json:"component_id"`
	OperatingSystem  string             `json:"operating_system"`
	Architecture     string             `json:"architecture"`
	Approvers        []RenderApprover   `json:"approvers"`
	Connections      []RenderConnection `json:"connections,omitempty"`
	Integrations     []string           `json:"integrations,omitempty"`
	CapabilityDigest string             `json:"capability_snapshot_digest,omitempty"`
	Profile          json.RawMessage    `json:"profile"`
	Files            []RenderFile       `json:"files,omitempty"`
}

// RenderFile is one nonsecret referenced file included in the rendered
// component result.
type RenderFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Data   []byte `json:"data"`
}

// RenderReviewItem is one plain review sentence emitted for the terminal
// renderer. The item never carries credential values or absolute file paths
// that reveal secret locations.
type RenderReviewItem struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

// RenderSecretPrompt is one secret prompt metadata entry emitted before secret
// collection. Metadata never carries secret bytes.
type RenderSecretPrompt struct {
	Slot     string `json:"slot"`
	Label    string `json:"label"`
	Required bool   `json:"required"`
}

// RenderResponse is one deterministic provider-owned render output. It
// contains the rendered provider profile document, referenced nonsecret files,
// review items and secret prompt metadata. The output never carries secret
// bytes or credential source paths.
type RenderResponse struct {
	APIVersion    string               `json:"api_version"`
	ComponentID   string               `json:"component_id"`
	Profile       json.RawMessage      `json:"profile"`
	Files         []RenderFile         `json:"files,omitempty"`
	ReviewItems   []RenderReviewItem   `json:"review_items,omitempty"`
	SecretPrompts []RenderSecretPrompt `json:"secret_prompts,omitempty"`
	RenderDigest  string               `json:"render_digest"`
}

// RenderMetadata is the nonsecret, digest-bound part of a render response that
// remains in the compiled installation for review and credential prompting.
type RenderMetadata struct {
	APIVersion    string               `json:"api_version"`
	ComponentID   string               `json:"component_id"`
	ReviewItems   []RenderReviewItem   `json:"review_items,omitempty"`
	SecretPrompts []RenderSecretPrompt `json:"secret_prompts,omitempty"`
	RenderDigest  string               `json:"render_digest"`
}

// Metadata returns the durable nonsecret projection of a render response.
func (response RenderResponse) Metadata() RenderMetadata {
	return RenderMetadata{
		APIVersion: response.APIVersion, ComponentID: response.ComponentID,
		ReviewItems:   append([]RenderReviewItem(nil), response.ReviewItems...),
		SecretPrompts: append([]RenderSecretPrompt(nil), response.SecretPrompts...), RenderDigest: response.RenderDigest,
	}
}

// Validate checks bounded render metadata.
func (metadata RenderMetadata) Validate() error {
	if metadata.APIVersion != RenderAPIVersion || !identifierPattern.MatchString(metadata.ComponentID) || !validDigest(metadata.RenderDigest) ||
		len(metadata.ReviewItems) > MaxActions || len(metadata.SecretPrompts) > MaxCredentialSlots {
		return errors.New("render metadata is invalid")
	}
	seen := map[string]bool{}
	for _, prompt := range metadata.SecretPrompts {
		if !identifierPattern.MatchString(prompt.Slot) || strings.TrimSpace(prompt.Label) == "" || seen[prompt.Slot] {
			return errors.New("render metadata secret prompt is invalid or duplicated")
		}
		seen[prompt.Slot] = true
	}
	for _, item := range metadata.ReviewItems {
		if strings.TrimSpace(item.Kind) == "" || strings.TrimSpace(item.Message) == "" || len(item.Message) > 4096 {
			return errors.New("render metadata review item is invalid")
		}
	}
	return nil
}

// Validate checks render request bounds and protocol invariants.
//
//nolint:cyclop // The render request is a closed nonsecret contract validated field by field.
func (request RenderRequest) Validate() error {
	if request.APIVersion != RenderAPIVersion || !identifierPattern.MatchString(request.ComponentID) {
		return errors.New("render request identity is invalid")
	}
	if request.OperatingSystem == "" || request.Architecture == "" {
		return errors.New("render request platform is invalid")
	}
	if len(request.Approvers) == 0 || len(request.Approvers) > MaxCredentialSlots {
		return errors.New("render request approver count is invalid")
	}
	if len(request.Connections) > 32 || len(request.Integrations) > 32 || len(request.Profile) == 0 ||
		len(request.Profile) > MaxMessageBytes || !json.Valid(request.Profile) || len(request.Files) > MaxFiles {
		return errors.New("render request collection exceeds limits")
	}
	seenApprovers := map[string]bool{}
	for _, approver := range request.Approvers {
		if !identifierPattern.MatchString(approver.ID) || strings.TrimSpace(approver.Account) == "" || seenApprovers[approver.ID] {
			return errors.New("render request approver is invalid or duplicated")
		}
		seenApprovers[approver.ID] = true
	}
	seenConnections := map[string]bool{}
	for _, connection := range request.Connections {
		if !identifierPattern.MatchString(connection.ID) || !identifierPattern.MatchString(connection.ClientID) || seenConnections[connection.ID] {
			return errors.New("render request connection is invalid or duplicated")
		}
		if !slices.Contains([]string{"local_account", "container", "remote"}, connection.TargetKind) {
			return errors.New("render request connection target kind is invalid")
		}
		seenConnections[connection.ID] = true
	}
	seenFiles := map[string]bool{}
	for _, file := range request.Files {
		if !safeRenderRelative(file.Path) || seenFiles[file.Path] || !validDigest(file.SHA256) ||
			file.SHA256 != digest(file.Data) || len(file.Data) > MaxMessageBytes {
			return errors.New("render request file is invalid or duplicated")
		}
		seenFiles[file.Path] = true
	}
	if request.CapabilityDigest != "" && !validDigest(request.CapabilityDigest) {
		return errors.New("render request capability snapshot digest is invalid")
	}
	return nil
}

// Validate checks the render response for size, structure, and digest binding.
//
//nolint:cyclop // The render response is validated field by field against its trust boundary.
func (response RenderResponse) Validate() error {
	if response.APIVersion != RenderAPIVersion || !identifierPattern.MatchString(response.ComponentID) {
		return errors.New("render response identity is invalid")
	}
	if len(response.Profile) == 0 || len(response.Profile) > MaxMessageBytes {
		return errors.New("render response profile is invalid")
	}
	if !json.Valid(response.Profile) {
		return errors.New("render response profile is not valid JSON")
	}
	if len(response.Files) > MaxFiles || len(response.ReviewItems) > MaxActions || len(response.SecretPrompts) > MaxCredentialSlots {
		return errors.New("render response exceeds size limits")
	}
	seenPaths := map[string]bool{}
	for _, file := range response.Files {
		if !safeRenderRelative(file.Path) || seenPaths[file.Path] {
			return errors.New("render response file path is invalid or duplicated")
		}
		if !validDigest(file.SHA256) || file.SHA256 != digest(file.Data) || len(file.Data) > MaxMessageBytes {
			return errors.New("render response file digest is invalid")
		}
		seenPaths[file.Path] = true
	}
	seenSlots := map[string]bool{}
	for _, prompt := range response.SecretPrompts {
		if !identifierPattern.MatchString(prompt.Slot) || strings.TrimSpace(prompt.Label) == "" || seenSlots[prompt.Slot] {
			return errors.New("render response secret prompt is invalid or duplicated")
		}
		seenSlots[prompt.Slot] = true
	}
	if !validDigest(response.RenderDigest) {
		return errors.New("render response digest is invalid")
	}
	expected, err := response.CalculateRenderDigest()
	if err != nil || expected != response.RenderDigest {
		return errors.New("render response digest does not bind response content")
	}
	return nil
}

// CalculateRenderDigest computes the deterministic digest that binds the
// rendered profile bytes, referenced files, review items, and secret prompt
// metadata.
func (response RenderResponse) CalculateRenderDigest() (string, error) {
	files := append([]RenderFile{}, response.Files...)
	reviewItems := append([]RenderReviewItem{}, response.ReviewItems...)
	secretPrompts := append([]RenderSecretPrompt{}, response.SecretPrompts...)
	values := struct {
		ComponentID   string               `json:"component_id"`
		Profile       json.RawMessage      `json:"profile"`
		Files         []RenderFile         `json:"files"`
		ReviewItems   []RenderReviewItem   `json:"review_items"`
		SecretPrompts []RenderSecretPrompt `json:"secret_prompts"`
	}{response.ComponentID, response.Profile, files, reviewItems, secretPrompts}
	data, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum), nil
}

// safeRenderRelative rejects unsafe render file destinations.
func safeRenderRelative(path string) bool {
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, `\`) || strings.ContainsRune(path, 0) {
		return false
	}
	if filepath.Clean(path) != path || path == "." {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}
