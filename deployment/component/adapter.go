// Package component provides provider-neutral setup adapter mechanics. Each
// provider supplies its own closed profile version and ownership envelope.
package component

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/osolmaz/unyolo/deployment/api"
	deploymentruntime "github.com/osolmaz/unyolo/deployment/runtime"
	"github.com/osolmaz/unyolo/internal/config/client"
	"github.com/osolmaz/unyolo/internal/config/secretfile"
	"github.com/osolmaz/unyolo/internal/strictjson"
)

const maxSecretBytes = 1024 * 1024

// Config is the provider-owned adapter boundary.
type Config struct {
	ComponentID     string
	ProfileAPI      string
	AllowedPaths    []string
	AllowedServices []string
	AllowedAccounts []string
	AllowedGroups   []string
	BackupDirectory string
	ClientProbe     func(context.Context, api.AgentBinding, Client, string) error
}

// Account declares one provider-owned service identity.
type Account struct {
	Name  string `json:"name"`
	Group string `json:"group"`
	Home  string `json:"home"`
	Shell string `json:"shell"`
}

// Group declares one provider-owned access group and exact members.
type Group struct {
	Name    string   `json:"name"`
	Members []string `json:"members,omitempty"`
}

// Reference selects one digest-bound request file.
type Reference struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Directory declares one provider-owned directory.
type Directory struct {
	ID          string `json:"id"`
	Destination string `json:"destination"`
	Mode        uint32 `json:"mode"`
	Owner       string `json:"owner"`
	Group       string `json:"group"`
}

// ManagedFile declares one complete nonsecret file.
type ManagedFile struct {
	ID          string    `json:"id"`
	Source      Reference `json:"source"`
	Destination string    `json:"destination"`
	Mode        uint32    `json:"mode"`
	Owner       string    `json:"owner"`
	Group       string    `json:"group"`
	Restart     bool      `json:"restart,omitempty"`
}

// Credential declares one write-only credential slot destination.
type Credential struct {
	Slot        string `json:"slot"`
	Destination string `json:"destination"`
	Mode        uint32 `json:"mode"`
	Owner       string `json:"owner"`
	Group       string `json:"group"`
	Encoding    string `json:"encoding"`
	ClientID    string `json:"client_id,omitempty"`
	Action      string `json:"action,omitempty"`
}

// SecretEntry binds one desired identity to one write-only secret slot.
type SecretEntry struct {
	Identity string `json:"identity"`
	Slot     string `json:"slot"`
	Rotate   bool   `json:"rotate,omitempty"`
}

// SecretStore declares one authoritative named client or approver store.
type SecretStore struct {
	ID          string        `json:"id"`
	Destination string        `json:"destination"`
	Mode        uint32        `json:"mode"`
	Owner       string        `json:"owner"`
	Group       string        `json:"group"`
	Entries     []SecretEntry `json:"entries"`
}

// Client declares one generated private client V1 document.
type Client struct {
	AgentID     string `json:"agent_id"`
	BrokerName  string `json:"broker_name"`
	EnvPrefix   string `json:"env_prefix"`
	SecretSlot  string `json:"secret_slot"`
	Endpoint    string `json:"endpoint"`
	GitEndpoint string `json:"git_endpoint,omitempty"`
}

// Profile is the common resource section embedded in each provider profile.
type Profile struct {
	APIVersion   string        `json:"api_version"`
	Accounts     []Account     `json:"accounts,omitempty"`
	Groups       []Group       `json:"groups,omitempty"`
	Directories  []Directory   `json:"directories,omitempty"`
	Files        []ManagedFile `json:"files,omitempty"`
	Credentials  []Credential  `json:"credentials,omitempty"`
	SecretStores []SecretStore `json:"secret_stores,omitempty"`
	Clients      []Client      `json:"clients,omitempty"`
	Services     []string      `json:"services,omitempty"`
}

// Serve handles one setup-component request and writes one response.
func Serve(ctx context.Context, input io.Reader, output io.Writer, config Config) error {
	var request api.Request
	if err := deploymentruntime.ReadFrame(input, &request); err != nil {
		return err
	}
	if err := request.Validate(); err != nil {
		return err
	}
	if request.ComponentID != config.ComponentID {
		return errors.New("component adapter identity mismatch")
	}
	var profile Profile
	if err := strictjson.Decode(request.Profile, &profile, true); err != nil {
		return errors.New("component deployment profile is invalid")
	}
	if response, handled, err := dispatchWithoutInspection(ctx, request, profile, config); handled || err != nil {
		if err != nil {
			return err
		}
		return deploymentruntime.WriteFrame(output, response)
	}
	state, err := inspect(ctx, request, profile, config)
	if err != nil {
		return err
	}
	response, err := dispatch(ctx, request, profile, config, state)
	if err != nil {
		return err
	}
	return deploymentruntime.WriteFrame(output, response)
}

func dispatchWithoutInspection(ctx context.Context, request api.Request, profile Profile, config Config) (api.Response, bool, error) {
	switch request.Action {
	case api.ActionValidate, api.ActionRollback, api.ActionFinalize:
		if err := validateProfile(profile, config, request.Agents); err != nil {
			return api.Response{}, true, err
		}
		response := api.Response{APIVersion: api.APIVersion, ComponentID: config.ComponentID, Status: "valid"}
		if request.Action == api.ActionRollback {
			if err := rollback(ctx, config, request.RollbackHandle); err != nil {
				return api.Response{}, true, err
			}
			response.Status, response.PlanDigest = "rolled_back", request.PlanDigest
		}
		if request.Action == api.ActionFinalize {
			if err := finalizeBackup(config, request.RollbackHandle); err != nil {
				return api.Response{}, true, err
			}
			response.Status, response.PlanDigest = "finalized", request.PlanDigest
		}
		return response, true, nil
	case api.ActionPlan, api.ActionApply, api.ActionVerify:
		return api.Response{}, false, nil
	default:
		return api.Response{}, true, errors.New("unsupported component action")
	}
}

type inspected struct {
	actions      []api.PlannedAction
	credentials  []api.CredentialAction
	storeSecrets map[string][]byte
	planDigest   string
	fingerprints []string
	files        map[string]api.File
	agents       map[string]api.AgentBinding
}

//nolint:cyclop // Inspection projects each bounded resource kind into one canonical component plan.
func inspect(ctx context.Context, request api.Request, profile Profile, config Config) (inspected, error) {
	if err := validateProfile(profile, config, request.Agents); err != nil {
		return inspected{}, err
	}
	state := inspected{files: map[string]api.File{}, agents: map[string]api.AgentBinding{}, storeSecrets: map[string][]byte{}}
	for _, file := range request.Files {
		state.files[file.Path] = file
	}
	for _, agent := range request.Agents {
		state.agents[agent.ID] = agent
	}
	for _, group := range profile.Groups {
		fingerprint := groupFingerprint(ctx, group)
		state.fingerprints = append(state.fingerprints, "group:"+group.Name+":"+fingerprint)
		if !groupMatches(ctx, group) {
			state.actions = append(state.actions, api.PlannedAction{
				ID: "group-" + group.Name, Type: "reconcile", Risk: "high",
				Resource: api.Resource{Kind: "group", ID: group.Name}, CurrentState: resourceState(fingerprint),
				DesiredDigest: digest([]byte(strings.Join(group.Members, "\x00"))),
			})
		}
	}
	for _, account := range profile.Accounts {
		fingerprint := accountFingerprint(ctx, account)
		state.fingerprints = append(state.fingerprints, "account:"+account.Name+":"+fingerprint)
		if !accountMatches(ctx, account) {
			state.actions = append(state.actions, api.PlannedAction{
				ID: "account-" + account.Name, Type: "reconcile", Risk: "high",
				Resource: api.Resource{Kind: "account", ID: account.Name}, CurrentState: resourceState(fingerprint),
				DesiredDigest: digest([]byte(account.Group + "\x00" + account.Home + "\x00" + account.Shell)),
			})
		}
	}
	for _, directory := range profile.Directories {
		fingerprint := pathFingerprint(directory.Destination)
		state.fingerprints = append(state.fingerprints, "directory:"+directory.ID+":"+fingerprint)
		if matchesDirectory(directory) {
			continue
		}
		state.actions = append(state.actions, api.PlannedAction{
			ID: "directory-" + directory.ID, Type: "reconcile", Risk: "medium",
			Resource: api.Resource{Kind: "directory", ID: directory.ID, Path: directory.Destination}, CurrentState: resourceState(fingerprint),
			DesiredDigest: metadataDigest(directory.Mode, directory.Owner, directory.Group),
		})
	}
	for _, managed := range profile.Files {
		fingerprint := pathFingerprint(managed.Destination)
		state.fingerprints = append(state.fingerprints, "file:"+managed.ID+":"+fingerprint)
		source, exists := state.files[managed.Source.Path]
		if !exists || source.SHA256 != managed.Source.SHA256 {
			return inspected{}, fmt.Errorf("managed file %q source is unavailable", managed.ID)
		}
		current := fileDigest(managed.Destination)
		if current == managed.Source.SHA256 && matchesMetadata(managed.Destination, managed.Mode, managed.Owner, managed.Group) {
			continue
		}
		state.actions = append(state.actions, api.PlannedAction{
			ID: "file-" + managed.ID, Type: "replace", Risk: "medium",
			Resource: api.Resource{Kind: "file", ID: managed.ID, Path: managed.Destination}, CurrentState: resourceState(fingerprint),
			CurrentDigest: current, DesiredDigest: managed.Source.SHA256, Restart: managed.Restart,
		})
	}
	for _, credential := range profile.Credentials {
		fingerprint := pathFingerprint(credential.Destination)
		state.fingerprints = append(state.fingerprints, "credential:"+credential.Slot+":"+fingerprint)
		action := "retain"
		_, err := os.Lstat(credential.Destination)
		if errors.Is(err, os.ErrNotExist) {
			action = "install"
		} else if err != nil {
			return inspected{}, errors.New("inspect installed component credential")
		} else if credential.Action == "rotate" {
			action = "rotate"
		} else {
			installed, readErr := readInstalledCredential(credential)
			if readErr != nil || len(installed) == 0 {
				action = "install"
			}
			clear(installed)
		}
		state.credentials = append(state.credentials, api.CredentialAction{Slot: credential.Slot, Action: action})
		if action != "retain" || !matchesMetadata(credential.Destination, credential.Mode, credential.Owner, credential.Group) {
			actionType := action
			if actionType == "retain" {
				actionType = "reconcile"
			}
			state.actions = append(state.actions, api.PlannedAction{
				ID: "credential-" + credential.Slot, Type: actionType, Risk: "high",
				Resource: api.Resource{Kind: "credential", ID: credential.Slot, Path: credential.Destination}, CurrentState: resourceState(fingerprint),
				DesiredDigest: metadataDigest(credential.Mode, credential.Owner, credential.Group),
			})
		}
	}
	for _, store := range profile.SecretStores {
		fingerprint := pathFingerprint(store.Destination)
		state.fingerprints = append(state.fingerprints, "secret-store:"+store.ID+":"+fingerprint)
		current, readErr := readNamedStore(store.Destination)
		if readErr != nil {
			return inspected{}, readErr
		}
		desired := map[string]bool{}
		changed := len(current) != len(store.Entries)
		for _, entry := range store.Entries {
			desired[entry.Identity] = true
			action := "retain"
			secret, exists := current[entry.Identity]
			if !exists {
				action = "install"
			} else if entry.Rotate {
				action = "rotate"
			}
			state.credentials = append(state.credentials, api.CredentialAction{Slot: entry.Slot, Action: action})
			if action == "retain" {
				state.storeSecrets[entry.Slot] = []byte(secret)
			} else {
				changed = true
			}
		}
		for identity := range current {
			if !desired[identity] {
				changed = true
			}
		}
		if changed || !matchesMetadata(store.Destination, store.Mode, store.Owner, store.Group) {
			state.actions = append(state.actions, api.PlannedAction{
				ID: "secret-store-" + store.ID, Type: "reconcile", Risk: "high",
				Resource: api.Resource{Kind: "secret_store", ID: store.ID, Path: store.Destination}, CurrentState: resourceState(fingerprint),
				DesiredDigest: metadataDigest(store.Mode, store.Owner, store.Group), Restart: true,
			})
		}
	}
	for _, client := range profile.Clients {
		agent := state.agents[client.AgentID]
		path, err := clientconfig.Path(agent.Home, client.BrokerName)
		if err != nil {
			return inspected{}, err
		}
		fingerprint := pathFingerprint(path)
		state.fingerprints = append(state.fingerprints, "client:"+client.AgentID+":"+fingerprint)
		var expected []byte
		if credential, found := credentialBySlot(profile.Credentials, client.SecretSlot); found {
			expected, _ = readInstalledCredential(credential)
		} else if stored := state.storeSecrets[client.SecretSlot]; len(stored) > 0 {
			expected = append([]byte(nil), stored...)
		}
		current := clientCurrent(path, agent.Home, client, expected)
		if credentialAction(state.credentials, client.SecretSlot) != "retain" {
			current = false
		}
		clear(expected)
		if current {
			continue
		}
		state.actions = append(state.actions, api.PlannedAction{
			ID: "client-" + client.AgentID, Type: "replace", Risk: "medium",
			Resource: api.Resource{Kind: "client", ID: client.AgentID, Path: path}, CurrentState: resourceState(fingerprint),
			DesiredDigest: metadataDigest(0o600, agent.UnixUser, agent.UnixUser),
		})
	}
	slices.SortFunc(state.actions, func(a, b api.PlannedAction) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(state.credentials, func(a, b api.CredentialAction) int { return strings.Compare(a.Slot, b.Slot) })
	slices.Sort(state.fingerprints)
	state.planDigest = planDigest(state.actions, state.credentials, state.fingerprints)
	return state, nil
}

//nolint:cyclop // Adapter dispatch is an exhaustive closed operation switch.
func dispatch(ctx context.Context, request api.Request, profile Profile, config Config, state inspected) (api.Response, error) {
	base := api.Response{
		APIVersion: api.APIVersion, ComponentID: config.ComponentID,
		PlanDigest: state.planDigest, Actions: state.actions, Credentials: state.credentials,
	}
	switch request.Action {
	case api.ActionValidate:
		return api.Response{APIVersion: api.APIVersion, ComponentID: config.ComponentID, Status: "valid"}, nil
	case api.ActionPlan:
		base.Status = "planned"
		return base, nil
	case api.ActionApply:
		if request.PlanDigest != state.planDigest {
			return api.Response{}, errors.New("component plan is stale")
		}
		handle, err := apply(ctx, request, profile, config, state)
		if err != nil {
			var rolledBack rolledBackApplyError
			if errors.As(err, &rolledBack) {
				base.Status, base.BlockedReason = "rolled_back", "component apply failed and was rolled back"
				return base, nil
			}
			return api.Response{}, err
		}
		base.Status, base.RollbackHandle = "applied", handle
		return base, nil
	case api.ActionVerify:
		evidence, err := verify(ctx, profile, config, state, request.ProbeExecutable)
		if err != nil {
			return api.Response{}, err
		}
		return api.Response{APIVersion: api.APIVersion, ComponentID: config.ComponentID, Status: "verified", Verification: evidence}, nil
	case api.ActionRollback:
		if err := rollback(ctx, config, request.RollbackHandle); err != nil {
			return api.Response{}, err
		}
		return api.Response{APIVersion: api.APIVersion, ComponentID: config.ComponentID, Status: "rolled_back", PlanDigest: request.PlanDigest}, nil
	case api.ActionFinalize:
		return api.Response{}, errors.New("finalize requires lifecycle dispatch")
	default:
		return api.Response{}, errors.New("unsupported component action")
	}
}

//nolint:cyclop // Provider-owned profiles are checked exhaustively before any host inspection or mutation.
func validateProfile(profile Profile, config Config, agents []api.AgentBinding) error {
	if profile.APIVersion != config.ProfileAPI {
		return errors.New("component deployment profile API is invalid")
	}
	if len(profile.Accounts) > 32 || len(profile.Groups) > 64 || len(profile.Directories) > 64 || len(profile.Files) > 128 || len(profile.Credentials) > 32 || len(profile.SecretStores) > 16 || len(profile.Clients) > 32 || len(profile.Services) > 16 {
		return errors.New("component deployment profile exceeds limits")
	}
	agentIDs := map[string]bool{}
	for _, agent := range agents {
		agentIDs[agent.ID] = true
	}
	seenIDs, seenPaths, seenSlots := map[string]bool{}, map[string]bool{}, map[string]bool{}
	seenAccounts, seenGroups := map[string]bool{}, map[string]bool{}
	for _, account := range profile.Accounts {
		if !slices.Contains(config.AllowedAccounts, account.Name) || !slices.Contains(config.AllowedGroups, account.Group) || seenAccounts[account.Name] ||
			!filepath.IsAbs(account.Home) || filepath.Clean(account.Home) != account.Home || !filepath.IsAbs(account.Shell) || filepath.Clean(account.Shell) != account.Shell {
			return errors.New("component service account is outside ownership")
		}
		seenAccounts[account.Name] = true
	}
	for _, group := range profile.Groups {
		if !slices.Contains(config.AllowedGroups, group.Name) || seenGroups[group.Name] || len(group.Members) > 64 {
			return errors.New("component group is outside ownership")
		}
		seenGroups[group.Name] = true
		seenMembers := map[string]bool{}
		for _, member := range group.Members {
			if member == "" || seenMembers[member] {
				return errors.New("component group member is invalid or duplicated")
			}
			seenMembers[member] = true
		}
	}
	for _, directory := range profile.Directories {
		if !validResource(directory.ID, directory.Destination, directory.Mode, directory.Owner, directory.Group, config.AllowedPaths, seenIDs, seenPaths) {
			return errors.New("component directory is invalid or outside ownership")
		}
	}
	for _, managed := range profile.Files {
		if !validResource(managed.ID, managed.Destination, managed.Mode, managed.Owner, managed.Group, config.AllowedPaths, seenIDs, seenPaths) || managed.Source.Path == "" || managed.Source.SHA256 == "" {
			return errors.New("component file is invalid or outside ownership")
		}
	}
	for _, credential := range profile.Credentials {
		if !validResource("credential-"+credential.Slot, credential.Destination, credential.Mode, credential.Owner, credential.Group, config.AllowedPaths, seenIDs, seenPaths) ||
			credential.Slot == "" || seenSlots[credential.Slot] || !slices.Contains([]string{"", "retain", "rotate"}, credential.Action) ||
			!slices.Contains([]string{"raw", "client_secret_file"}, credential.Encoding) ||
			(credential.Encoding == "client_secret_file" && credential.ClientID == "") {
			return errors.New("component credential is invalid or duplicated")
		}
		seenSlots[credential.Slot] = true
	}
	for _, store := range profile.SecretStores {
		if store.ID == "" || !validResource("secret-store-"+store.ID, store.Destination, store.Mode, store.Owner, store.Group, config.AllowedPaths, seenIDs, seenPaths) || len(store.Entries) > 64 {
			return errors.New("component named secret store is invalid")
		}
		seenEntries := map[string]bool{}
		for _, entry := range store.Entries {
			if entry.Identity == "" || entry.Slot == "" || seenEntries[entry.Identity] || seenSlots[entry.Slot] {
				return errors.New("component named secret entry is invalid or duplicated")
			}
			seenEntries[entry.Identity], seenSlots[entry.Slot] = true, true
		}
	}
	for _, client := range profile.Clients {
		if !agentIDs[client.AgentID] || !seenSlots[client.SecretSlot] || client.BrokerName == "" || client.EnvPrefix == "" {
			return errors.New("component client binding is invalid")
		}
	}
	for _, service := range profile.Services {
		if !slices.Contains(config.AllowedServices, service) {
			return errors.New("component service is outside ownership")
		}
	}
	return nil
}

func readNamedStore(path string) (map[string]string, error) {
	data, err := readBoundedNoFollow(path, maxSecretBytes)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, errors.New("installed named secret store is unavailable")
	}
	values, err := secretfile.ParseBytesWithOptions(data, secretfile.ParseOptions{AllowEmpty: true})
	clear(data)
	if err != nil {
		return nil, errors.New("installed named secret store is invalid")
	}
	return values, nil
}

func validResource(id, path string, mode uint32, owner, group string, allowed []string, ids, paths map[string]bool) bool {
	if id == "" || ids[id] || path == "" || paths[path] || mode > 0o777 || mode&0o002 != 0 || owner == "" || group == "" || !ownedPath(path, allowed) {
		return false
	}
	ids[id], paths[path] = true, true
	return true
}

func ownedPath(path string, prefixes []string) bool {
	return deploymentruntime.OwnedPath(path, prefixes)
}

func planDigest(actions []api.PlannedAction, credentials []api.CredentialAction, fingerprints []string) string {
	data, _ := json.Marshal(struct {
		Actions      []api.PlannedAction    `json:"actions"`
		Credentials  []api.CredentialAction `json:"credentials"`
		Fingerprints []string               `json:"fingerprints"`
	}{actions, credentials, fingerprints})
	return digest(data)
}

func digest(data []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(data)) }

func fileDigest(path string) string {
	data, err := readBoundedNoFollow(path, api.MaxMessageBytes)
	if err != nil {
		return ""
	}
	return digest(data)
}

func metadataDigest(mode uint32, owner, group string) string {
	return digest([]byte(fmt.Sprintf("%04o:%s:%s", mode, owner, group)))
}

// ResourceFingerprint returns a secret-safe current identity for one adapter
// resource. When includeContent is false, regular-file bytes are excluded.
func ResourceFingerprint(ctx context.Context, resource api.Resource, includeContent bool) string {
	switch resource.Kind {
	case "account":
		return accountFingerprint(ctx, Account{Name: resource.ID})
	case "group":
		return groupFingerprint(ctx, Group{Name: resource.ID})
	default:
		if resource.Path == "" {
			return "unavailable"
		}
		return fingerprintPath(resource.Path, includeContent)
	}
}

func resourceState(fingerprint string) string {
	if fingerprint == "missing" {
		return "missing"
	}
	return "present"
}

func pathFingerprint(path string) string { return fingerprintPath(path, true) }

func fingerprintPath(path string, includeContent bool) string {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "missing"
	}
	if err != nil {
		return "unavailable"
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "unsupported"
	}
	hash := sha256.New()
	_, _ = fmt.Fprintf(hash, "%d:%d:%d:%d:%d:%d:%d", stat.Dev, stat.Ino, stat.Uid, stat.Gid, info.Mode(), info.Size(), info.ModTime().UnixNano())
	if info.Mode().IsRegular() && includeContent {
		file, openErr := os.Open(path) // #nosec G304 -- provider-owned validated path.
		if openErr != nil {
			return "unavailable"
		}
		written, copyErr := io.Copy(hash, io.LimitReader(file, maxSecretBytes*16+1))
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || written > maxSecretBytes*16 {
			return "unavailable"
		}
	}
	return fmt.Sprintf("sha256:%x", hash.Sum(nil))
}

func groupFingerprint(ctx context.Context, value Group) string {
	group, err := user.LookupGroup(value.Name)
	if err != nil {
		return "missing"
	}
	members, err := hostAccountBackend().GroupMembers(ctx, value.Name)
	if err != nil {
		return "unavailable"
	}
	return digest([]byte(group.Gid + "\x00" + strings.Join(members, "\x00")))
}

func accountFingerprint(ctx context.Context, value Account) string {
	account, err := user.Lookup(value.Name)
	if err != nil {
		return "missing"
	}
	shell, _ := accountShell(ctx, value.Name)
	return digest([]byte(account.Uid + "\x00" + account.Gid + "\x00" + account.HomeDir + "\x00" + shell))
}

func groupMatches(ctx context.Context, value Group) bool {
	if _, err := user.LookupGroup(value.Name); err != nil {
		return false
	}
	members, err := hostAccountBackend().GroupMembers(ctx, value.Name)
	if err != nil {
		return false
	}
	desired := append([]string(nil), value.Members...)
	slices.Sort(desired)
	return slices.Equal(members, desired)
}

func accountMatches(ctx context.Context, value Account) bool {
	account, err := user.Lookup(value.Name)
	if err != nil || filepath.Clean(account.HomeDir) != value.Home {
		return false
	}
	group, err := user.LookupGroup(value.Group)
	if err != nil || account.Gid != group.Gid {
		return false
	}
	shell, err := accountShell(ctx, value.Name)
	return err == nil && shell == value.Shell
}

func accountShell(ctx context.Context, name string) (string, error) {
	record, err := hostAccountBackend().Inspect(ctx, name)
	if err != nil {
		return "", err
	}
	return record.Shell, nil
}

func matchesDirectory(value Directory) bool {
	info, err := os.Stat(value.Destination)
	return err == nil && info.IsDir() && info.Mode().Perm() == os.FileMode(value.Mode) && matchesOwner(info, value.Owner, value.Group)
}

func matchesMetadata(path string, mode uint32, owner, group string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm() == os.FileMode(mode) && matchesOwner(info, owner, group)
}

func matchesOwner(info os.FileInfo, owner, group string) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	uid, gid, err := resolveOwner(owner, group)
	return err == nil && int(stat.Uid) == uid && int(stat.Gid) == gid
}

func resolveOwner(owner, group string) (int, int, error) {
	resolvedUser, err := user.Lookup(owner)
	if err != nil {
		return 0, 0, err
	}
	resolvedGroup, err := user.LookupGroup(group)
	if err != nil {
		return 0, 0, err
	}
	uid, err := strconv.Atoi(resolvedUser.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.Atoi(resolvedGroup.Gid)
	return uid, gid, err
}

func clientCurrent(path, home string, spec Client, expectedSecret []byte) bool {
	value, err := clientconfig.ReadPath(path, home)
	if err != nil || value.AgentEndpoint != spec.Endpoint || value.GitEndpoint != spec.GitEndpoint {
		return false
	}
	return len(expectedSecret) == 0 || value.SharedSecret == strings.TrimSpace(string(expectedSecret))
}

func credentialBySlot(values []Credential, slot string) (Credential, bool) {
	index := slices.IndexFunc(values, func(value Credential) bool { return value.Slot == slot })
	if index < 0 {
		return Credential{}, false
	}
	return values[index], true
}
