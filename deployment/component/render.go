package component

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"

	deploymentruntime "github.com/osolmaz/unyolo/deployment/runtime"

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
	if len(request.Profile) == 0 {
		request.Profile = append([]byte(nil), profileTemplate...)
	}
	if len(request.Files) == 0 {
		request.Files = renderAssetFiles(assets)
	}
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
	renderedAssets := cloneAssets(assets)
	if err := renderPolicyAssets(&profile, renderedAssets, clientsForRender(request)); err != nil {
		return api.RenderResponse{}, err
	}
	bindRenderedAssetDigests(&profile, renderedAssets)
	renderedProfile, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return api.RenderResponse{}, err
	}
	renderedProfile = append(renderedProfile, '\n')
	files := renderAssetFiles(renderedAssets)
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

// ServeRender handles one stateless framed render exchange.
func ServeRender(input io.Reader, output io.Writer, renderer Renderer) error {
	if renderer == nil {
		return errors.New("component renderer is unavailable")
	}
	var request api.RenderRequest
	if err := deploymentruntime.ReadFrame(input, &request); err != nil {
		return err
	}
	if err := request.Validate(); err != nil {
		return err
	}
	assets := make(map[string][]byte, len(request.Files))
	for _, file := range request.Files {
		assets[file.Path] = append([]byte(nil), file.Data...)
	}
	response, err := renderer.Render(request, request.Profile, assets)
	if err != nil {
		return err
	}
	if response.ComponentID != request.ComponentID {
		return errors.New("component render response identity mismatch")
	}
	return deploymentruntime.WriteFrame(output, response)
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

func cloneAssets(assets map[string][]byte) map[string][]byte {
	result := make(map[string][]byte, len(assets))
	for name, data := range assets {
		result[name] = append([]byte(nil), data...)
	}
	return result
}

func clientsForRender(request api.RenderRequest) []string {
	var result []string
	for _, connection := range request.Connections {
		if slices.Contains(connection.Providers, request.ComponentID) {
			result = append(result, connection.ClientID)
		}
	}
	slices.Sort(result)
	return result
}

func renderPolicyAssets(profile *Profile, assets map[string][]byte, clients []string) error {
	paths := map[string]string{}
	for _, managed := range profile.Files {
		name := path.Base(managed.Source.Path)
		paths[name] = managed.Source.Path
		if name == "policy-manifest.json" || !strings.Contains(name, "policy") && name != "scope.json" {
			continue
		}
		data, exists := assets[managed.Source.Path]
		if !exists {
			return fmt.Errorf("managed policy asset %q is unavailable", managed.Source.Path)
		}
		updated, err := rewriteClientArrays(data, clients)
		if err != nil {
			return fmt.Errorf("render policy asset %q: %w", managed.Source.Path, err)
		}
		assets[managed.Source.Path] = updated
	}
	manifestPath, profilePath, policyPath := paths["policy-manifest.json"], paths["policy-profile.json"], paths["scope.json"]
	if manifestPath == "" || profilePath == "" || policyPath == "" {
		return nil
	}
	manifestData, exists := assets[manifestPath]
	if !exists {
		return errors.New("policy manifest asset is unavailable")
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return err
	}
	manifest["profile_digest"] = renderDigest(assets[profilePath])
	manifest["policy_digest"] = renderDigest(assets[policyPath])
	updated, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	assets[manifestPath] = append(updated, '\n')
	return nil
}

func rewriteClientArrays(data []byte, clients []string) ([]byte, error) {
	var validated any
	if err := json.Unmarshal(data, &validated); err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	result := make([]string, 0, len(lines)+len(clients))
	replacements := 0
	for index := 0; index < len(lines); index++ {
		line := lines[index]
		trimmedLine := strings.TrimSpace(line)
		if strings.Contains(trimmedLine, `"clients": [`) && trimmedLine != `"clients": [` {
			start := strings.Index(line, "[")
			end := strings.LastIndex(line, "]")
			if start < 0 || end < start {
				return nil, errors.New("inline policy client list is not closed")
			}
			encoded := make([]string, len(clients))
			for clientIndex, client := range clients {
				value, err := json.Marshal(client)
				if err != nil {
					return nil, err
				}
				encoded[clientIndex] = string(value)
			}
			result = append(result, line[:start+1]+strings.Join(encoded, ", ")+line[end:])
			replacements++
			continue
		}
		if trimmedLine != `"clients": [` {
			result = append(result, line)
			continue
		}
		result = append(result, line)
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))] + "  "
		closing := index + 1
		for ; closing < len(lines); closing++ {
			trimmed := strings.TrimSpace(lines[closing])
			if trimmed == "]" || trimmed == "]," {
				break
			}
		}
		if closing == len(lines) {
			return nil, errors.New("policy client list is not closed")
		}
		for clientIndex, client := range clients {
			encoded, err := json.Marshal(client)
			if err != nil {
				return nil, err
			}
			suffix := ","
			if clientIndex == len(clients)-1 {
				suffix = ""
			}
			result = append(result, indent+string(encoded)+suffix)
		}
		result = append(result, lines[closing])
		index, replacements = closing, replacements+1
	}
	if replacements == 0 {
		return nil, errors.New("managed policy contains no client list")
	}
	return []byte(strings.Join(result, "\n")), nil
}

func bindRenderedAssetDigests(profile *Profile, assets map[string][]byte) {
	for index := range profile.Files {
		data, exists := assets[profile.Files[index].Source.Path]
		if exists {
			profile.Files[index].Source.SHA256 = renderDigest(data)
		}
	}
}

func renderDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hexEncode(sum[:])
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
