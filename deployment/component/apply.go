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

	"github.com/osolmaz/brokerkit/deployment/api"
	"github.com/osolmaz/brokerkit/internal/config/client"
	"github.com/osolmaz/brokerkit/internal/strictjson"
)

type backup struct {
	APIVersion string        `json:"api_version"`
	ID         string        `json:"id"`
	Entries    []backupEntry `json:"entries"`
}

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
	record, err := createBackup(config, paths)
	if err != nil {
		return "", err
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, rollback(config, record.ID))
		}
	}()
	secrets, err := readSecrets(request.Secrets)
	if err != nil {
		return "", err
	}
	defer clearSecrets(secrets)
	if err := applyGroups(ctx, profile.Groups); err != nil {
		return "", err
	}
	if err := applyAccounts(ctx, profile.Accounts); err != nil {
		return "", err
	}
	if err := applyGroupMembers(ctx, profile.Groups); err != nil {
		return "", err
	}
	if err := applyDirectories(profile.Directories); err != nil {
		return "", err
	}
	if err := applyFiles(profile.Files, state.files); err != nil {
		return "", err
	}
	installed, err := applyCredentials(profile.Credentials, state.credentials, secrets)
	if err != nil {
		return "", err
	}
	defer clearSecrets(installed)
	if err := applyClients(profile.Clients, state.agents, installed); err != nil {
		return "", err
	}
	return record.ID, nil
}

func changedPaths(profile Profile, state inspected) []string {
	changed := map[string]bool{}
	for _, action := range state.actions {
		if action.Resource.Path != "" {
			changed[action.Resource.Path] = true
		}
	}
	for _, credential := range profile.Credentials {
		for _, action := range state.credentials {
			if credential.Slot == action.Slot && action.Action == "install" {
				changed[credential.Destination] = true
			}
		}
	}
	result := make([]string, 0, len(changed))
	for path := range changed {
		result = append(result, path)
	}
	slices.Sort(result)
	return result
}

func createBackup(config Config, paths []string) (backup, error) {
	if config.BackupDirectory == "" || !ownedPath(config.BackupDirectory, config.AllowedPaths) {
		return backup{}, errors.New("component backup directory is outside ownership")
	}
	if err := os.MkdirAll(config.BackupDirectory, 0o700); err != nil {
		return backup{}, err
	}
	id, err := randomID()
	if err != nil {
		return backup{}, err
	}
	record := backup{APIVersion: "brokerkit.io/component-backup/v1", ID: id}
	for _, path := range paths {
		entry, entryErr := snapshotPath(path)
		if entryErr != nil {
			return backup{}, entryErr
		}
		record.Entries = append(record.Entries, entry)
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
	if runtime.GOOS != "linux" {
		for _, value := range values {
			if !groupMatches(value) {
				return errors.New("automatic group membership is supported only on Linux")
			}
		}
		return nil
	}
	for _, value := range values {
		for _, member := range value.Members {
			if memberInGroup(member, value.Name) {
				continue
			}
			if output, err := exec.CommandContext(ctx, "usermod", "--append", "--groups", value.Name, member).CombinedOutput(); err != nil { // #nosec G204 -- validated exact group and user arguments.
				return fmt.Errorf("add component group member: %w: %s", err, strings.TrimSpace(string(output)))
			}
		}
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
		if err := os.MkdirAll(value.Destination, os.FileMode(value.Mode)); err != nil {
			return err
		}
		uid, gid, err := resolveOwner(value.Owner, value.Group)
		if err != nil {
			return err
		}
		if err := os.Chown(value.Destination, uid, gid); err != nil {
			return err
		}
		if err := os.Chmod(value.Destination, os.FileMode(value.Mode)); err != nil {
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

func applyCredentials(values []Credential, actions []api.CredentialAction, supplied map[string][]byte) (map[string][]byte, error) {
	result := map[string][]byte{}
	for _, value := range values {
		action := credentialAction(actions, value.Slot)
		var raw []byte
		if action == "install" {
			raw = supplied[value.Slot]
			if len(raw) == 0 {
				clearSecrets(result)
				return nil, fmt.Errorf("credential slot %q was not supplied", value.Slot)
			}
			body := encodeCredential(value, raw)
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
		}
		result[value.Slot] = append([]byte(nil), raw...)
	}
	return result, nil
}

func encodeCredential(value Credential, raw []byte) []byte {
	if value.Encoding == "client_secret_file" {
		return []byte(value.ClientID + " = " + strings.TrimSpace(string(raw)) + "\n")
	}
	return append([]byte(nil), raw...)
}

func readInstalledCredential(value Credential) ([]byte, error) {
	data, err := os.ReadFile(value.Destination) // #nosec G304 -- provider-owned credential path.
	if err != nil || len(data) > maxSecretBytes {
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

func applyClients(values []Client, agents map[string]api.AgentBinding, secrets map[string][]byte) error {
	for _, value := range values {
		agent := agents[value.AgentID]
		_, err := clientconfig.WriteForHomeOwner(clientconfig.Config{
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
func verify(ctx context.Context, profile Profile, config Config, state inspected) ([]string, error) {
	var evidence []string
	for _, group := range profile.Groups {
		if !groupMatches(group) {
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
		if _, err := os.Stat(credential.Destination); err != nil {
			return nil, fmt.Errorf("credential slot %q is unavailable", credential.Slot)
		}
		evidence = append(evidence, "credential "+credential.Slot+" is installed")
	}
	for _, value := range profile.Clients {
		agent := state.agents[value.AgentID]
		path, _ := clientconfig.Path(agent.Home, value.BrokerName)
		credential, _ := credentialBySlot(profile.Credentials, value.SecretSlot)
		expected, err := readInstalledCredential(credential)
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
		if err := probe(ctx, agent, value); err != nil {
			return nil, err
		}
		evidence = append(evidence, "client "+value.AgentID+" completed authenticated real-agent discovery")
	}
	slices.Sort(evidence)
	return evidence, nil
}

//nolint:cyclop // Rollback restores every bounded backup record in reverse mutation order.
func rollback(config Config, handle string) error {
	if len(handle) != 32 {
		return errors.New("component rollback handle is invalid")
	}
	path := filepath.Join(config.BackupDirectory, handle+".json")
	data, err := os.ReadFile(path) // #nosec G304 -- handle is fixed-format below a fixed provider backup root.
	if err != nil {
		return err
	}
	var record backup
	if err := strictjson.Decode(data, &record, true); err != nil || record.ID != handle || record.APIVersion != "brokerkit.io/component-backup/v1" {
		return errors.New("component rollback backup is invalid")
	}
	for index := len(record.Entries) - 1; index >= 0; index-- {
		entry := record.Entries[index]
		if !ownedPath(entry.Path, config.AllowedPaths) && !isAgentClientPath(entry.Path) {
			return errors.New("component rollback path exceeds ownership")
		}
		if !entry.Existed {
			if err := os.RemoveAll(entry.Path); err != nil {
				return err
			}
			continue
		}
		if entry.Directory {
			if err := os.MkdirAll(entry.Path, os.FileMode(entry.Mode)); err != nil {
				return err
			}
			if err := os.Chown(entry.Path, entry.UID, entry.GID); err != nil {
				return err
			}
			continue
		}
		if err := writeAtomic(entry.Path, entry.Data, os.FileMode(entry.Mode), entry.UID, entry.GID); err != nil {
			return err
		}
	}
	return os.Remove(path)
}

func isAgentClientPath(path string) bool {
	return strings.Contains(path, string(filepath.Separator)+".config"+string(filepath.Separator)) && strings.HasSuffix(path, "client.json")
}

func writeAtomic(path string, data []byte, mode os.FileMode, uid, gid int) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".component-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer func() { _ = os.Remove(temporary) }()
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
	return os.Rename(temporary, path)
}

func randomID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func clearSecrets(values map[string][]byte) {
	for _, value := range values {
		clear(value)
	}
}
