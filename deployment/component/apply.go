package component

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"

	"github.com/osolmaz/unyolo/auth"
	"github.com/osolmaz/unyolo/deployment/api"
	"github.com/osolmaz/unyolo/internal/config/client"
	"github.com/osolmaz/unyolo/internal/config/secretfile"
	"github.com/osolmaz/unyolo/internal/strictjson"
	"golang.org/x/sys/unix"
)

type backup struct {
	APIVersion string          `json:"api_version"`
	ID         string          `json:"id"`
	Entries    []backupEntry   `json:"entries"`
	Accounts   []accountBackup `json:"accounts,omitempty"`
	Groups     []groupBackup   `json:"groups,omitempty"`
}

type accountBackup struct {
	Name    string `json:"name"`
	Existed bool   `json:"existed"`
}

type groupBackup struct {
	Name    string   `json:"name"`
	Existed bool     `json:"existed"`
	Members []string `json:"members,omitempty"`
}

type rolledBackApplyError struct{ cause error }

func (err rolledBackApplyError) Error() string { return err.cause.Error() }
func (err rolledBackApplyError) Unwrap() error { return err.cause }

type backupEntry struct {
	Path      string `json:"path"`
	Existed   bool   `json:"existed"`
	Mode      uint32 `json:"mode,omitempty"`
	UID       int    `json:"uid,omitempty"`
	GID       int    `json:"gid,omitempty"`
	Data      []byte `json:"data,omitempty"`
	Directory bool   `json:"directory,omitempty"`
}

//nolint:cyclop // Ordered account, file, credential, and client phases share one rollback boundary.
func apply(ctx context.Context, request api.Request, profile Profile, config Config, state inspected) (handle string, returnErr error) {
	paths := changedPaths(profile, state)
	record, err := createBackup(ctx, config, paths, profile)
	if err != nil {
		return "", err
	}
	defer func() {
		if returnErr != nil {
			if rollbackErr := rollback(ctx, config, record.ID); rollbackErr != nil {
				returnErr = errors.Join(returnErr, rollbackErr)
			} else {
				returnErr = rolledBackApplyError{cause: returnErr}
			}
		}
	}()
	secrets, err := readSecrets(request.Secrets)
	if err != nil {
		return "", err
	}
	defer clearSecrets(secrets)
	planned := plannedActionIDs(state.actions)
	groups := plannedValues(profile.Groups, planned, "group-", func(value Group) string { return value.Name })
	if err := applyGroups(ctx, groups); err != nil {
		return "", err
	}
	accounts := plannedValues(profile.Accounts, planned, "account-", func(value Account) string { return value.Name })
	if err := applyAccounts(ctx, accounts); err != nil {
		return "", err
	}
	if err := applyGroupMembers(ctx, groups); err != nil {
		return "", err
	}
	directories := plannedValues(profile.Directories, planned, "directory-", func(value Directory) string { return value.ID })
	if err := applyDirectories(directories); err != nil {
		return "", err
	}
	files := plannedValues(profile.Files, planned, "file-", func(value ManagedFile) string { return value.ID })
	if err := applyFiles(files, state.files); err != nil {
		return "", err
	}
	installed, err := applyCredentials(profile.Credentials, state.credentials, secrets, planned)
	if err != nil {
		return "", err
	}
	defer clearSecrets(installed)
	storeSecrets, err := applySecretStores(profile.SecretStores, state.credentials, secrets, planned)
	if err != nil {
		return "", err
	}
	defer clearSecrets(storeSecrets)
	for slot, secret := range storeSecrets {
		installed[slot] = secret
	}
	clients := plannedValues(profile.Clients, planned, "client-", func(value Client) string { return value.AgentID })
	if err := applyClients(clients, state.agents, installed); err != nil {
		return "", err
	}
	return record.ID, nil
}

func plannedActionIDs(actions []api.PlannedAction) map[string]bool {
	result := make(map[string]bool, len(actions))
	for _, action := range actions {
		result[action.ID] = true
	}
	return result
}

func plannedValues[T any](values []T, planned map[string]bool, prefix string, id func(T) string) []T {
	result := make([]T, 0, len(values))
	for _, value := range values {
		if planned[prefix+id(value)] {
			result = append(result, value)
		}
	}
	return result
}

func changedPaths(profile Profile, state inspected) []string {
	changed := map[string]bool{}
	for _, action := range state.actions {
		if action.Resource.Path != "" {
			changed[action.Resource.Path] = true
		}
	}
	result := make([]string, 0, len(changed))
	for path := range changed {
		result = append(result, path)
	}
	slices.Sort(result)
	return result
}

func createBackup(ctx context.Context, config Config, paths []string, profile Profile) (backup, error) {
	if config.BackupDirectory == "" || !ownedPath(config.BackupDirectory, config.AllowedPaths) {
		return backup{}, errors.New("component backup directory is outside ownership")
	}
	id, err := randomID()
	if err != nil {
		return backup{}, err
	}
	record := backup{APIVersion: "unyolo.io/component-backup/v1", ID: id}
	record.Accounts, record.Groups, err = snapshotIdentityBackups(ctx, profile)
	if err != nil {
		return backup{}, err
	}
	for _, path := range paths {
		entry, entryErr := snapshotPath(path)
		if entryErr != nil {
			return backup{}, entryErr
		}
		record.Entries = append(record.Entries, entry)
	}
	if err := ensureDirectoryNoFollow(config.BackupDirectory, 0o700, -1, -1); err != nil {
		return backup{}, err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return backup{}, err
	}
	if err := writeAtomic(filepath.Join(config.BackupDirectory, id+".json"), data, 0o600, -1, -1); err != nil {
		return backup{}, err
	}
	return record, nil
}

func snapshotIdentityBackups(ctx context.Context, profile Profile) ([]accountBackup, []groupBackup, error) {
	accounts := make([]accountBackup, 0, len(profile.Accounts))
	for _, account := range profile.Accounts {
		_, err := user.Lookup(account.Name)
		if err != nil && !isUnknownUser(err) {
			return nil, nil, errors.New("inspect component account for rollback")
		}
		accounts = append(accounts, accountBackup{Name: account.Name, Existed: err == nil})
	}
	groups := make([]groupBackup, 0, len(profile.Groups))
	for _, group := range profile.Groups {
		_, err := user.LookupGroup(group.Name)
		if err != nil && !isUnknownGroup(err) {
			return nil, nil, errors.New("inspect component group for rollback")
		}
		entry := groupBackup{Name: group.Name, Existed: err == nil}
		if entry.Existed {
			entry.Members, err = groupMemberNames(ctx, group.Name)
			if err != nil {
				return nil, nil, errors.New("inspect component group members for rollback")
			}
		}
		groups = append(groups, entry)
	}
	return accounts, groups, nil
}

func snapshotPath(path string) (backupEntry, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return backupEntry{Path: path}, nil
	}
	if err != nil {
		return backupEntry{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return backupEntry{}, errors.New("component backup ownership is unavailable")
	}
	entry := backupEntry{Path: path, Existed: true, Mode: uint32(info.Mode().Perm()), UID: int(stat.Uid), GID: int(stat.Gid), Directory: info.IsDir()}
	if info.Mode().IsRegular() {
		entry.Data, err = os.ReadFile(path) // #nosec G304 -- provider-owned validated path.
		if err != nil || len(entry.Data) > maxSecretBytes*16 {
			return backupEntry{}, errors.New("component backup file is unavailable or too large")
		}
	} else if !info.IsDir() {
		return backupEntry{}, errors.New("component backup path is not regular")
	}
	return entry, nil
}

func readSecrets(descriptors []api.SecretDescriptor) (map[string][]byte, error) {
	result := map[string][]byte{}
	for _, descriptor := range descriptors {
		file := os.NewFile(uintptr(descriptor.FD), descriptor.Name)
		if file == nil {
			clearSecrets(result)
			return nil, errors.New("component credential descriptor is unavailable")
		}
		data, err := io.ReadAll(io.LimitReader(file, maxSecretBytes+1))
		closeErr := file.Close()
		if err != nil || closeErr != nil || len(data) == 0 || len(data) > maxSecretBytes {
			clearSecrets(result)
			return nil, errors.New("component credential input is invalid")
		}
		result[descriptor.Name] = data
	}
	return result, nil
}

func applyGroups(ctx context.Context, values []Group) error {
	for _, value := range values {
		if _, err := user.LookupGroup(value.Name); err == nil {
			continue
		}
		if runtime.GOOS != "linux" {
			return errors.New("automatic service group creation is supported only on Linux")
		}
		if output, err := exec.CommandContext(ctx, "groupadd", "--system", value.Name).CombinedOutput(); err != nil { // #nosec G204 -- validated provider-owned name is one fixed command argument.
			return fmt.Errorf("create service group: %w: %s", err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func applyAccounts(ctx context.Context, values []Account) error {
	for _, value := range values {
		if _, err := user.Lookup(value.Name); err == nil {
			if !accountMatches(ctx, value) {
				return fmt.Errorf("service account %q does not match the profile", value.Name)
			}
			continue
		}
		if runtime.GOOS != "linux" {
			return errors.New("automatic service account creation is supported only on Linux")
		}
		arguments := []string{"--system", "--home-dir", value.Home, "--shell", value.Shell, "--gid", value.Group, value.Name}
		if output, err := exec.CommandContext(ctx, "useradd", arguments...).CombinedOutput(); err != nil { // #nosec G204 -- validated provider-owned fields are arguments to a fixed command.
			return fmt.Errorf("create service account: %w: %s", err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func applyGroupMembers(ctx context.Context, values []Group) error {
	for _, value := range values {
		current, err := groupMemberNames(ctx, value.Name)
		if err != nil {
			return fmt.Errorf("inspect component group members: %w", err)
		}
		desired := append([]string(nil), value.Members...)
		slices.Sort(desired)
		for _, member := range desired {
			if slices.Contains(current, member) {
				continue
			}
			if err := editGroupMember(ctx, value.Name, member, true); err != nil {
				return err
			}
		}
		for _, member := range current {
			if slices.Contains(desired, member) {
				continue
			}
			if err := editGroupMember(ctx, value.Name, member, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func editGroupMember(ctx context.Context, group, member string, add bool) error {
	var command *exec.Cmd
	if runtime.GOOS == "darwin" {
		action := "-d"
		if add {
			action = "-a"
		}
		command = exec.CommandContext(ctx, "dseditgroup", "-o", "edit", action, member, "-t", "user", group) // #nosec G204 -- validated exact user and group arguments.
	} else if add {
		command = exec.CommandContext(ctx, "usermod", "--append", "--groups", group, member) // #nosec G204 -- validated exact user and group arguments.
	} else {
		command = exec.CommandContext(ctx, "gpasswd", "--delete", member, group) // #nosec G204 -- validated exact user and group arguments.
	}
	output, err := command.CombinedOutput()
	if err != nil {
		action := "remove"
		if add {
			action = "add"
		}
		return fmt.Errorf("%s component group member: %w: %s", action, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func memberInGroup(name, groupName string) bool {
	account, err := user.Lookup(name)
	if err != nil {
		return false
	}
	group, err := user.LookupGroup(groupName)
	if err != nil {
		return false
	}
	groups, err := account.GroupIds()
	return err == nil && slices.Contains(groups, group.Gid)
}

func applyDirectories(values []Directory) error {
	for _, value := range values {
		uid, gid, err := resolveOwner(value.Owner, value.Group)
		if err != nil {
			return err
		}
		if err := ensureDirectoryNoFollow(value.Destination, os.FileMode(value.Mode), uid, gid); err != nil {
			return err
		}
	}
	return nil
}

func applyFiles(values []ManagedFile, files map[string]api.File) error {
	for _, value := range values {
		source := files[value.Source.Path]
		uid, gid, err := resolveOwner(value.Owner, value.Group)
		if err != nil {
			return err
		}
		if err := writeAtomic(value.Destination, source.Data, os.FileMode(value.Mode), uid, gid); err != nil {
			return err
		}
	}
	return nil
}

//nolint:cyclop // Credential install, rotation, retention, and reviewed metadata repair share secret-clearing paths.
func applyCredentials(values []Credential, actions []api.CredentialAction, supplied map[string][]byte, planned map[string]bool) (map[string][]byte, error) {
	result := map[string][]byte{}
	for _, value := range values {
		action := credentialAction(actions, value.Slot)
		var raw []byte
		if action == "install" || action == "rotate" {
			raw = supplied[value.Slot]
			if len(raw) == 0 {
				clearSecrets(result)
				return nil, fmt.Errorf("credential slot %q was not supplied", value.Slot)
			}
			body, err := encodeCredential(value, raw)
			if err != nil {
				clearSecrets(result)
				return nil, err
			}
			uid, gid, err := resolveOwner(value.Owner, value.Group)
			if err != nil {
				clear(body)
				clearSecrets(result)
				return nil, err
			}
			if err := writeAtomic(value.Destination, body, os.FileMode(value.Mode), uid, gid); err != nil {
				clear(body)
				clearSecrets(result)
				return nil, err
			}
			clear(body)
		} else {
			var err error
			raw, err = readInstalledCredential(value)
			if err != nil {
				clearSecrets(result)
				return nil, err
			}
			if planned["credential-"+value.Slot] {
				uid, gid, ownerErr := resolveOwner(value.Owner, value.Group)
				if ownerErr != nil {
					clear(raw)
					clearSecrets(result)
					return nil, ownerErr
				}
				if err := setFileMetadataNoFollow(value.Destination, os.FileMode(value.Mode), uid, gid); err != nil {
					clear(raw)
					clearSecrets(result)
					return nil, err
				}
			}
		}
		result[value.Slot] = append([]byte(nil), raw...)
	}
	return result, nil
}

func encodeCredential(value Credential, raw []byte) ([]byte, error) {
	if value.Encoding == "client_secret_file" {
		secret := string(raw)
		if secret != strings.TrimSpace(secret) || len(raw) < auth.MinimumSecretBytes || strings.ContainsAny(secret, "\x00\r\n") {
			return nil, errors.New("broker client credential must be one unpadded secret of at least 32 bytes")
		}
		return []byte(value.ClientID + " = " + secret + "\n"), nil
	}
	return append([]byte(nil), raw...), nil
}

func readInstalledCredential(value Credential) ([]byte, error) {
	data, err := readBoundedNoFollow(value.Destination, maxSecretBytes)
	if err != nil || len(data) == 0 {
		return nil, errors.New("installed component credential is unavailable")
	}
	if value.Encoding == "client_secret_file" {
		secret, parseErr := clientconfig.SecretFromData(data, value.ClientID)
		clear(data)
		if parseErr != nil {
			return nil, errors.New("installed component credential is invalid")
		}
		return []byte(secret), nil
	}
	return data, nil
}

func applySecretStores(values []SecretStore, actions []api.CredentialAction, supplied map[string][]byte, planned map[string]bool) (map[string][]byte, error) {
	result := map[string][]byte{}
	for _, value := range values {
		current, err := readNamedStore(value.Destination)
		if err != nil {
			clearSecrets(result)
			return nil, err
		}
		desired := make(map[string]string, len(value.Entries))
		for _, entry := range value.Entries {
			action := credentialAction(actions, entry.Slot)
			var secret string
			if action == "install" || action == "rotate" {
				raw := supplied[entry.Slot]
				secret = string(raw)
				if secret != strings.TrimSpace(secret) || len(raw) < auth.MinimumSecretBytes || strings.ContainsAny(secret, "\x00\r\n") {
					clearSecrets(result)
					return nil, fmt.Errorf("named secret slot %q was not supplied safely", entry.Slot)
				}
			} else {
				secret = current[entry.Identity]
				if secret == "" {
					clearSecrets(result)
					return nil, fmt.Errorf("retained named secret %q is unavailable", entry.Identity)
				}
			}
			desired[entry.Identity] = secret
			result[entry.Slot] = []byte(secret)
		}
		if planned["secret-store-"+value.ID] {
			body, renderErr := secretfile.RenderWithOptions(desired, secretfile.ParseOptions{AllowEmpty: true})
			if renderErr != nil {
				clearSecrets(result)
				return nil, renderErr
			}
			uid, gid, ownerErr := resolveOwner(value.Owner, value.Group)
			if ownerErr != nil {
				clear(body)
				clearSecrets(result)
				return nil, ownerErr
			}
			if err := writeAtomic(value.Destination, body, os.FileMode(value.Mode), uid, gid); err != nil {
				clear(body)
				clearSecrets(result)
				return nil, err
			}
			clear(body)
		}
	}
	return result, nil
}

func applyClients(values []Client, agents map[string]api.AgentBinding, secrets map[string][]byte) error {
	for _, value := range values {
		agent := agents[value.AgentID]
		path, err := clientconfig.Path(agent.Home, value.BrokerName)
		if err != nil {
			return err
		}
		if clientCurrent(path, agent.Home, value, secrets[value.SecretSlot]) {
			continue
		}
		_, err = clientconfig.WriteForHomeOwner(clientconfig.Config{
			BrokerName: value.BrokerName, EnvPrefix: value.EnvPrefix, ClientID: agent.ClientID,
			Endpoint: value.Endpoint, GitEndpoint: value.GitEndpoint,
			Secret: strings.TrimSpace(string(secrets[value.SecretSlot])), HomeDir: agent.Home,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func credentialAction(values []api.CredentialAction, slot string) string {
	for _, value := range values {
		if value.Slot == slot {
			return value.Action
		}
	}
	return ""
}

//nolint:cyclop // Verification checks every declared resource kind and returns bounded evidence.
func verify(ctx context.Context, profile Profile, config Config, state inspected, probeExecutable string) ([]string, error) {
	var evidence []string
	for _, group := range profile.Groups {
		if !groupMatches(ctx, group) {
			return nil, fmt.Errorf("group %q does not match", group.Name)
		}
		evidence = append(evidence, "group "+group.Name+" matches")
	}
	for _, account := range profile.Accounts {
		if !accountMatches(ctx, account) {
			return nil, fmt.Errorf("account %q does not match", account.Name)
		}
		evidence = append(evidence, "account "+account.Name+" matches")
	}
	for _, directory := range profile.Directories {
		if !matchesDirectory(directory) {
			return nil, fmt.Errorf("directory %q does not match", directory.ID)
		}
		evidence = append(evidence, "directory "+directory.ID+" matches")
	}
	for _, managed := range profile.Files {
		if fileDigest(managed.Destination) != managed.Source.SHA256 || !matchesMetadata(managed.Destination, managed.Mode, managed.Owner, managed.Group) {
			return nil, fmt.Errorf("file %q does not match", managed.ID)
		}
		evidence = append(evidence, "file "+managed.ID+" matches")
	}
	for _, credential := range profile.Credentials {
		if !matchesMetadata(credential.Destination, credential.Mode, credential.Owner, credential.Group) {
			return nil, fmt.Errorf("credential slot %q is unavailable or has unsafe metadata", credential.Slot)
		}
		evidence = append(evidence, "credential "+credential.Slot+" is installed")
	}
	for _, store := range profile.SecretStores {
		values, err := readNamedStore(store.Destination)
		if err != nil || len(values) != len(store.Entries) || !matchesMetadata(store.Destination, store.Mode, store.Owner, store.Group) {
			return nil, fmt.Errorf("named secret store %q does not match", store.ID)
		}
		for _, entry := range store.Entries {
			if values[entry.Identity] == "" {
				return nil, fmt.Errorf("named secret store %q is missing identity %q", store.ID, entry.Identity)
			}
		}
		evidence = append(evidence, "named secret store "+store.ID+" matches")
	}
	for _, value := range profile.Clients {
		agent := state.agents[value.AgentID]
		path, _ := clientconfig.Path(agent.Home, value.BrokerName)
		credential, found := credentialBySlot(profile.Credentials, value.SecretSlot)
		var expected []byte
		var err error
		if found {
			expected, err = readInstalledCredential(credential)
		} else {
			expected = append([]byte(nil), state.storeSecrets[value.SecretSlot]...)
			if len(expected) == 0 {
				err = errors.New("installed named client credential is unavailable")
			}
		}
		if err != nil {
			return nil, err
		}
		current := clientCurrent(path, agent.Home, value, expected)
		clear(expected)
		if !current {
			return nil, fmt.Errorf("client %q does not match", value.AgentID)
		}
		probe := config.ClientProbe
		if probe == nil {
			probe = runClientProbe
		}
		if err := probe(ctx, agent, value, probeExecutable); err != nil {
			return nil, err
		}
		evidence = append(evidence, "client "+value.AgentID+" completed authenticated real-agent discovery")
	}
	slices.Sort(evidence)
	return evidence, nil
}

//nolint:cyclop // Rollback restores every bounded backup record and identity change in reverse mutation order.
func rollback(ctx context.Context, config Config, handle string) error {
	if len(handle) != 32 {
		return errors.New("component rollback handle is invalid")
	}
	path := filepath.Join(config.BackupDirectory, handle+".json")
	data, err := os.ReadFile(path) // #nosec G304 -- handle is fixed-format below a fixed provider backup root.
	if err != nil {
		return err
	}
	var record backup
	if err := strictjson.Decode(data, &record, true); err != nil || record.ID != handle || record.APIVersion != "unyolo.io/component-backup/v1" {
		return errors.New("component rollback backup is invalid")
	}
	if err := rollbackIdentities(ctx, config, record); err != nil {
		return err
	}
	var backupAncestor *backupEntry
	for index := len(record.Entries) - 1; index >= 0; index-- {
		entry := record.Entries[index]
		if !ownedPath(entry.Path, config.AllowedPaths) && !isAgentClientPath(entry.Path) {
			return errors.New("component rollback path exceeds ownership")
		}
		if ownedPath(config.BackupDirectory, []string{entry.Path}) {
			entryCopy := entry
			backupAncestor = &entryCopy
			continue
		}
		if err := restoreBackupEntry(entry); err != nil {
			return err
		}
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	if backupAncestor != nil {
		return restoreBackupEntry(*backupAncestor)
	}
	return nil
}

func finalizeBackup(config Config, handle string) error {
	if len(handle) != 32 {
		return errors.New("component finalize handle is invalid")
	}
	path := filepath.Join(config.BackupDirectory, handle+".json")
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func restoreBackupEntry(entry backupEntry) error {
	if !entry.Existed {
		return removeAllNoFollow(entry.Path)
	}
	if entry.Directory {
		return ensureDirectoryNoFollow(entry.Path, os.FileMode(entry.Mode), entry.UID, entry.GID)
	}
	return writeAtomic(entry.Path, entry.Data, os.FileMode(entry.Mode), entry.UID, entry.GID)
}

func rollbackIdentities(ctx context.Context, config Config, record backup) error {
	if err := rollbackAccounts(ctx, config, record.Accounts); err != nil {
		return err
	}
	return rollbackGroups(ctx, config, record.Groups)
}

func rollbackAccounts(ctx context.Context, config Config, accounts []accountBackup) error {
	for index := len(accounts) - 1; index >= 0; index-- {
		entry := accounts[index]
		if entry.Existed {
			continue
		}
		if !slices.Contains(config.AllowedAccounts, entry.Name) {
			return errors.New("component rollback account exceeds ownership")
		}
		if _, err := user.Lookup(entry.Name); isUnknownUser(err) {
			continue
		} else if err != nil {
			return errors.New("inspect component rollback account")
		}
		if output, err := exec.CommandContext(ctx, "userdel", entry.Name).CombinedOutput(); err != nil { // #nosec G204 -- signed ownership and the backup bind this validated account name.
			return fmt.Errorf("remove component account: %w: %s", err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func rollbackGroups(ctx context.Context, config Config, groups []groupBackup) error {
	for index := len(groups) - 1; index >= 0; index-- {
		entry := groups[index]
		if !slices.Contains(config.AllowedGroups, entry.Name) {
			return errors.New("component rollback group exceeds ownership")
		}
		if !entry.Existed {
			if _, err := user.LookupGroup(entry.Name); isUnknownGroup(err) {
				continue
			} else if err != nil {
				return errors.New("inspect component rollback group")
			}
			if output, err := exec.CommandContext(ctx, "groupdel", entry.Name).CombinedOutput(); err != nil { // #nosec G204 -- signed ownership and the backup bind this validated group name.
				return fmt.Errorf("remove component group: %w: %s", err, strings.TrimSpace(string(output)))
			}
			continue
		}
		if err := restoreGroupMembers(ctx, entry); err != nil {
			return err
		}
	}
	return nil
}

func restoreGroupMembers(ctx context.Context, entry groupBackup) error {
	current, err := groupMemberNames(ctx, entry.Name)
	if err != nil {
		return err
	}
	for _, member := range entry.Members {
		if !slices.Contains(current, member) {
			if err := editGroupMember(ctx, entry.Name, member, true); err != nil {
				return err
			}
		}
	}
	for _, member := range current {
		if !slices.Contains(entry.Members, member) {
			if err := editGroupMember(ctx, entry.Name, member, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func isUnknownUser(err error) bool { return errors.As(err, new(user.UnknownUserError)) }

func isUnknownGroup(err error) bool { return errors.As(err, new(user.UnknownGroupError)) }

func isAgentClientPath(path string) bool {
	return strings.Contains(path, string(filepath.Separator)+".config"+string(filepath.Separator)) && strings.HasSuffix(path, "client.json")
}

//nolint:cyclop // Descriptor-relative creation keeps every write, ownership, sync, and rename failure explicit.
func writeAtomic(path string, data []byte, mode os.FileMode, uid, gid int) error {
	parent, err := openDirectoryNoFollow(filepath.Dir(path), true, 0o700)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	temporary, err := randomID()
	if err != nil {
		return err
	}
	temporary = ".component-" + temporary
	fd, err := unix.Openat(parent, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(mode.Perm()))
	if err != nil {
		return err
	}
	defer func() { _ = unix.Unlinkat(parent, temporary, 0) }()
	file := os.NewFile(uintptr(fd), temporary)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("create component temporary file")
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if uid >= 0 && gid >= 0 {
		if err := file.Chown(uid, gid); err != nil {
			_ = file.Close()
			return err
		}
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return unix.Renameat(parent, temporary, parent, filepath.Base(path))
}

func removeAllNoFollow(path string) error {
	parent, err := openDirectoryNoFollow(filepath.Dir(path), false, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	return removeAtNoFollow(parent, filepath.Base(path))
}

//nolint:cyclop // Descriptor-relative recursive removal handles missing, file, directory, read, close, and unlink states.
func removeAtNoFollow(parent int, name string) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(parent, name, &stat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, syscall.ENOENT) {
		return nil
	} else if err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return unix.Unlinkat(parent, name, 0)
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), name)
	if directory == nil {
		_ = unix.Close(fd)
		return errors.New("open component rollback directory")
	}
	entries, readErr := directory.ReadDir(-1)
	if readErr == nil {
		for _, entry := range entries {
			if err := removeAtNoFollow(fd, entry.Name()); err != nil {
				readErr = err
				break
			}
		}
	}
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	return unix.Unlinkat(parent, name, unix.AT_REMOVEDIR)
}

func setFileMetadataNoFollow(path string, mode os.FileMode, uid, gid int) error {
	parent, err := openDirectoryNoFollow(filepath.Dir(path), false, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	fd, err := unix.Openat(parent, filepath.Base(path), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("component credential path is not a regular file")
	}
	if err := unix.Fchown(fd, uid, gid); err != nil {
		return err
	}
	return unix.Fchmod(fd, uint32(mode.Perm()))
}

func ensureDirectoryNoFollow(path string, mode os.FileMode, uid, gid int) error {
	fd, err := openDirectoryNoFollow(path, true, mode)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	if uid >= 0 && gid >= 0 {
		if err := unix.Fchown(fd, uid, gid); err != nil {
			return err
		}
	}
	return unix.Fchmod(fd, uint32(mode.Perm()))
}

//nolint:cyclop // Each path component is opened with O_NOFOLLOW and optionally created before traversal continues.
func openDirectoryNoFollow(path string, create bool, mode os.FileMode) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, errors.New("component directory path is invalid")
	}
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(openErr, syscall.ENOENT) && create {
			if mkdirErr := unix.Mkdirat(fd, part, uint32(mode.Perm())); mkdirErr != nil && !errors.Is(mkdirErr, syscall.EEXIST) {
				_ = unix.Close(fd)
				return -1, mkdirErr
			}
			next, openErr = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, openErr
		}
		fd = next
	}
	return fd, nil
}

func randomID() (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func clearSecrets(values map[string][]byte) {
	for _, value := range values {
		clear(value)
	}
}
