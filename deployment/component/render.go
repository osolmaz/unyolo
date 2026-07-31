package component

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/osolmaz/unyolo/deployment/api"
)

// Renderer produces the provider profile, referenced files, review items, and
// secret-prompt metadata for one deterministic render request. Every
// implementation must be stateless and reject inputs it does not recognize.
type Renderer interface {
	Render(request api.RenderRequest, profileTemplate []byte, assets map[string][]byte) (api.RenderResponse, error)
}

// StandardRenderer is the shared component renderer. It fills authoritative
// client and approver stores, updates group membership, adjusts local clients
// per selected connection, and emits deterministic review items and secret
// prompt metadata from the provider-owned template.
type StandardRenderer struct{}

// Render performs the deterministic render exchange described by the
// setup-component render V1 API. It runs entirely without host state,
// network, or credential values.
//
//nolint:cyclop // Deterministic render binds every provider-owned resource before hashing.
func (StandardRenderer) Render(request api.RenderRequest, profileTemplate []byte, assets map[string][]byte) (api.RenderResponse, error) {
	if err := request.Validate(); err != nil {
		return api.RenderResponse{}, err
	}
	var profile Profile
	if err := decodeProfileTemplate(profileTemplate, &profile); err != nil {
		return api.RenderResponse{}, err
	}
	renderStandardIdentities(&profile, request)
	if err := renderStandardStores(&profile, request); err != nil {
		return api.RenderResponse{}, err
	}
	renderStandardClients(&profile, request)
	renderedProfile, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return api.RenderResponse{}, err
	}
	renderedProfile = append(renderedProfile, '\n')
	files := renderAssetFiles(assets)
	prompts := renderSecretPrompts(request.ComponentID, profile, request)
	reviewItems := renderReviewItems(request)
	response := api.RenderResponse{
		APIVersion: api.RenderAPIVersion, ComponentID: request.ComponentID, Profile: renderedProfile,
		Files: files, ReviewItems: reviewItems, SecretPrompts: prompts,
	}
	digest, err := response.CalculateRenderDigest()
	if err != nil {
		return api.RenderResponse{}, err
	}
	response.RenderDigest = digest
	if err := response.Validate(); err != nil {
		return api.RenderResponse{}, err
	}
	return response, nil
}

func decodeProfileTemplate(data []byte, value *Profile) error {
	if len(data) == 0 {
		return errors.New("provider profile template is empty")
	}
	if err := json.Unmarshal(data, value); err != nil {
		return fmt.Errorf("decode provider profile template: %w", err)
	}
	return nil
}

func renderStandardIdentities(profile *Profile, request api.RenderRequest) {
	localUsers := localUsersFor(request)
	approverAccounts := make([]string, 0, len(request.Approvers))
	for _, approver := range request.Approvers {
		approverAccounts = append(approverAccounts, approver.Account)
	}
	slices.Sort(localUsers)
	slices.Sort(approverAccounts)
	for index := range profile.Groups {
		switch {
		case strings.HasSuffix(profile.Groups[index].Name, "-agent"):
			profile.Groups[index].Members = append([]string(nil), localUsers...)
		case strings.HasSuffix(profile.Groups[index].Name, "-operator"):
			profile.Groups[index].Members = append([]string(nil), approverAccounts...)
		}
	}
}

func renderStandardStores(profile *Profile, request api.RenderRequest) error {
	var clientDestination, clientOwner, clientGroup string
	var clientMode uint32
	var operatorDestination, operatorOwner, operatorGroup string
	var operatorMode uint32
	kept := profile.Credentials[:0]
	for _, credential := range profile.Credentials {
		if credential.Encoding != "client_secret_file" {
			kept = append(kept, credential)
			continue
		}
		if strings.Contains(credential.Slot, "operator") {
			operatorDestination, operatorMode, operatorOwner, operatorGroup = credential.Destination, credential.Mode, credential.Owner, credential.Group
		} else {
			clientDestination, clientMode, clientOwner, clientGroup = credential.Destination, credential.Mode, credential.Owner, credential.Group
		}
	}
	profile.Credentials = kept
	if clientDestination == "" || operatorDestination == "" {
		return fmt.Errorf("component %q has no named secret store templates", request.ComponentID)
	}
	clientStore := SecretStore{ID: "clients", Destination: clientDestination, Mode: clientMode, Owner: clientOwner, Group: clientGroup}
	operatorStore := SecretStore{ID: "approvers", Destination: operatorDestination, Mode: operatorMode, Owner: operatorOwner, Group: operatorGroup}
	for _, connection := range request.Connections {
		if !slices.Contains(connection.Providers, request.ComponentID) {
			continue
		}
		clientStore.Entries = append(clientStore.Entries, SecretEntry{Identity: connection.ClientID, Slot: request.ComponentID + "-client-" + connection.ClientID})
	}
	for _, approver := range request.Approvers {
		operatorStore.Entries = append(operatorStore.Entries, SecretEntry{Identity: approver.ID, Slot: request.ComponentID + "-approver-" + approver.ID})
	}
	profile.SecretStores = []SecretStore{clientStore, operatorStore}
	return nil
}

func renderStandardClients(profile *Profile, request api.RenderRequest) {
	templateClient := Client{}
	if len(profile.Clients) > 0 {
		templateClient = profile.Clients[0]
	}
	profile.Clients = nil
	for _, connection := range request.Connections {
		if connection.TargetKind != "local_account" || !slices.Contains(connection.Providers, request.ComponentID) {
			continue
		}
		client := templateClient
		client.AgentID = connection.ID
		client.SecretSlot = request.ComponentID + "-client-" + connection.ClientID
		profile.Clients = append(profile.Clients, client)
	}
}

func localUsersFor(request api.RenderRequest) []string {
	var result []string
	for _, connection := range request.Connections {
		if connection.TargetKind != "local_account" || !slices.Contains(connection.Providers, request.ComponentID) {
			continue
		}
		if strings.TrimSpace(connection.UnixUser) != "" {
			result = append(result, connection.UnixUser)
		}
	}
	return result
}

func renderAssetFiles(assets map[string][]byte) []api.RenderFile {
	paths := make([]string, 0, len(assets))
	for path := range assets {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	files := make([]api.RenderFile, 0, len(paths))
	for _, path := range paths {
		data := assets[path]
		sum := sha256.Sum256(data)
		files = append(files, api.RenderFile{Path: path, SHA256: "sha256:" + hexEncode(sum[:]), Data: append([]byte(nil), data...)})
	}
	return files
}

func renderSecretPrompts(componentID string, profile Profile, request api.RenderRequest) []api.RenderSecretPrompt {
	prompts := make([]api.RenderSecretPrompt, 0)
	seen := map[string]bool{}
	for _, credential := range profile.Credentials {
		if credential.Encoding != "raw" || seen[credential.Slot] {
			continue
		}
		seen[credential.Slot] = true
		prompts = append(prompts, api.RenderSecretPrompt{Slot: credential.Slot, Label: credential.Slot, Required: true})
	}
	for _, connection := range request.Connections {
		if !slices.Contains(connection.Providers, componentID) {
			continue
		}
		slot := componentID + "-client-" + connection.ClientID
		if seen[slot] {
			continue
		}
		seen[slot] = true
		prompts = append(prompts, api.RenderSecretPrompt{Slot: slot, Label: slot, Required: false})
	}
	slices.SortFunc(prompts, func(a, b api.RenderSecretPrompt) int { return strings.Compare(a.Slot, b.Slot) })
	return prompts
}

func renderReviewItems(request api.RenderRequest) []api.RenderReviewItem {
	items := make([]api.RenderReviewItem, 0, len(request.Connections)+1)
	items = append(items, api.RenderReviewItem{Kind: "provider", Message: request.ComponentID + " will be installed"})
	for _, connection := range request.Connections {
		if !slices.Contains(connection.Providers, request.ComponentID) {
			continue
		}
		items = append(items, api.RenderReviewItem{Kind: "connection", Message: connection.ID + " connects to " + request.ComponentID})
	}
	slices.SortFunc(items, func(a, b api.RenderReviewItem) int { return strings.Compare(a.Message, b.Message) })
	return items
}

func hexEncode(data []byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, len(data)*2)
	for index, current := range data {
		result[index*2] = digits[current>>4]
		result[index*2+1] = digits[current&15]
	}
	return string(result)
}
