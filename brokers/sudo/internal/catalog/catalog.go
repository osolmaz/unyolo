// Package catalog validates and resolves the root-owned sudo command catalog.
package catalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/osolmaz/brokerkit/internal/strictjson"
)

const (
	Version            = 1
	maxCommands        = 1024
	maxArguments       = 64
	maxTargetUsers     = 16
	maxTimeoutSeconds  = 3600
	maxOutputBytes     = 1 << 20
	maxStringBytes     = 4096
	defaultCommandRisk = "high"
)

var (
	idPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	slotPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	userPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)
	envPattern  = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
)

type Command struct {
	ID               string            `json:"id"`
	Executable       string            `json:"executable"`
	Arguments        []Argument        `json:"arguments"`
	TargetUsers      []string          `json:"target_users"`
	WorkingDirectory string            `json:"working_directory"`
	TimeoutSeconds   int               `json:"timeout_seconds"`
	MaxOutputBytes   int               `json:"max_output_bytes"`
	Environment      map[string]string `json:"environment,omitempty"`
	Description      string            `json:"description,omitempty"`
	Risk             string            `json:"risk"`
}

type Argument struct {
	Literal   *string  `json:"literal,omitempty"`
	Slot      string   `json:"slot,omitempty"`
	Type      string   `json:"type,omitempty"`
	Minimum   *int64   `json:"minimum,omitempty"`
	Maximum   *int64   `json:"maximum,omitempty"`
	Values    []string `json:"values,omitempty"`
	Roots     []string `json:"roots,omitempty"`
	MustExist bool     `json:"must_exist,omitempty"`
	FileType  string   `json:"file_type,omitempty"`
}

type Snapshot struct {
	commands map[string]Command
	digest   string
}

type Resolved struct {
	CommandID        string
	TargetUser       string
	Executable       string
	Arguments        []string
	WorkingDirectory string
	Environment      map[string]string
	TimeoutSeconds   int
	MaxOutputBytes   int
	SlotValues       map[string]string
	CatalogDigest    string
}

type document struct {
	Version  int           `json:"version"`
	Commands *[]rawCommand `json:"commands"`
}

type rawCommand struct {
	ID               string            `json:"id"`
	Executable       string            `json:"executable"`
	Arguments        *[]Argument       `json:"arguments"`
	TargetUsers      *[]string         `json:"target_users"`
	WorkingDirectory string            `json:"working_directory"`
	TimeoutSeconds   int               `json:"timeout_seconds"`
	MaxOutputBytes   *int              `json:"max_output_bytes"`
	Environment      map[string]string `json:"environment,omitempty"`
	Description      string            `json:"description,omitempty"`
	Risk             string            `json:"risk,omitempty"`
}

func Load(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- catalog path is operator configured.
	if err != nil {
		return nil, fmt.Errorf("read sudo catalog: %w", err)
	}
	return Parse(data)
}

func Parse(data []byte) (*Snapshot, error) {
	if err := strictjson.RejectDuplicateKeys(data); err != nil {
		return nil, fmt.Errorf("parse sudo catalog: %w", err)
	}
	var raw document
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse sudo catalog: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return nil, err
	}
	if raw.Version != Version {
		return nil, fmt.Errorf("sudo catalog version must be %d", Version)
	}
	if raw.Commands == nil || len(*raw.Commands) == 0 || len(*raw.Commands) > maxCommands {
		return nil, fmt.Errorf("sudo catalog must contain 1-%d commands", maxCommands)
	}
	commands := make([]Command, 0, len(*raw.Commands))
	seen := map[string]bool{}
	for index, value := range *raw.Commands {
		command, err := normalizeCommand(value)
		if err != nil {
			return nil, fmt.Errorf("commands[%d]: %w", index, err)
		}
		if seen[command.ID] {
			return nil, fmt.Errorf("commands[%d]: duplicate command id %q", index, command.ID)
		}
		seen[command.ID] = true
		commands = append(commands, command)
	}
	slices.SortFunc(commands, func(left, right Command) int { return strings.Compare(left.ID, right.ID) })
	encoded, err := json.Marshal(struct {
		Version  int       `json:"version"`
		Commands []Command `json:"commands"`
	}{Version: Version, Commands: commands})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(encoded)
	snapshot := &Snapshot{commands: make(map[string]Command, len(commands)), digest: hex.EncodeToString(sum[:])}
	for _, command := range commands {
		snapshot.commands[command.ID] = cloneCommand(command)
	}
	return snapshot, nil
}

func (s *Snapshot) Digest() string {
	if s == nil {
		return ""
	}
	return s.digest
}

func (s *Snapshot) Command(id string) (Command, bool) {
	if s == nil {
		return Command{}, false
	}
	command, ok := s.commands[id]
	return cloneCommand(command), ok
}

func (s *Snapshot) SlotNames() []string {
	if s == nil {
		return nil
	}
	seen := map[string]bool{}
	for _, command := range s.commands {
		for _, argument := range command.Arguments {
			if argument.Slot != "" {
				seen[argument.Slot] = true
			}
		}
	}
	values := make([]string, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	slices.Sort(values)
	return values
}

func (s *Snapshot) Resolve(commandID string, targetUser string, inputs map[string]json.RawMessage) (Resolved, error) {
	command, ok := s.Command(commandID)
	if !ok {
		return Resolved{}, errors.New("unknown command id")
	}
	if !slices.Contains(command.TargetUsers, targetUser) {
		return Resolved{}, errors.New("target user is not allowed for command")
	}
	argv := []string{command.Executable}
	values := map[string]string{}
	seen := map[string]bool{}
	for _, spec := range command.Arguments {
		if spec.Literal != nil {
			argv = append(argv, *spec.Literal)
			continue
		}
		raw, ok := inputs[spec.Slot]
		if !ok {
			return Resolved{}, fmt.Errorf("argument %q is required", spec.Slot)
		}
		value, err := resolveArgument(spec, raw)
		if err != nil {
			return Resolved{}, fmt.Errorf("argument %q: %w", spec.Slot, err)
		}
		seen[spec.Slot] = true
		values[spec.Slot] = value
		argv = append(argv, value)
	}
	for key := range inputs {
		if !seen[key] {
			return Resolved{}, fmt.Errorf("argument %q is not declared by command", key)
		}
	}
	return Resolved{
		CommandID: command.ID, TargetUser: targetUser, Executable: command.Executable, Arguments: argv,
		WorkingDirectory: command.WorkingDirectory, Environment: cloneMap(command.Environment), TimeoutSeconds: command.TimeoutSeconds,
		MaxOutputBytes: command.MaxOutputBytes, SlotValues: values, CatalogDigest: s.digest,
	}, nil
}

func (s *Snapshot) ValidateResolved(resolved Resolved) error {
	if s == nil || resolved.CatalogDigest != s.digest {
		return errors.New("resolved command catalog digest does not match")
	}
	command, ok := s.Command(resolved.CommandID)
	if !ok {
		return errors.New("resolved command no longer exists")
	}
	inputs := map[string]json.RawMessage{}
	for _, argument := range command.Arguments {
		if argument.Slot == "" {
			continue
		}
		value, ok := resolved.SlotValues[argument.Slot]
		if !ok {
			return errors.New("resolved command is missing a slot value")
		}
		if argument.Type == "integer" {
			inputs[argument.Slot] = json.RawMessage(value)
		} else {
			encoded, _ := json.Marshal(value)
			inputs[argument.Slot] = encoded
		}
	}
	again, err := s.Resolve(resolved.CommandID, resolved.TargetUser, inputs)
	if err != nil {
		return err
	}
	if again.Executable != resolved.Executable || !slices.Equal(again.Arguments, resolved.Arguments) ||
		again.WorkingDirectory != resolved.WorkingDirectory || !maps.Equal(again.Environment, resolved.Environment) ||
		again.TimeoutSeconds != resolved.TimeoutSeconds || again.MaxOutputBytes != resolved.MaxOutputBytes ||
		!maps.Equal(again.SlotValues, resolved.SlotValues) {
		return errors.New("resolved command does not match the current catalog")
	}
	return nil
}

func normalizeCommand(raw rawCommand) (Command, error) {
	if !idPattern.MatchString(raw.ID) {
		return Command{}, errors.New("id must be 1-64 lowercase alphanumeric/hyphen characters")
	}
	executable, err := validateExecutable(raw.Executable)
	if err != nil {
		return Command{}, err
	}
	if raw.Arguments == nil || len(*raw.Arguments) > maxArguments {
		return Command{}, fmt.Errorf("arguments is required and may contain at most %d entries", maxArguments)
	}
	arguments := append([]Argument(nil), (*raw.Arguments)...)
	if err := validateArguments(arguments); err != nil {
		return Command{}, err
	}
	if raw.TargetUsers == nil || len(*raw.TargetUsers) == 0 || len(*raw.TargetUsers) > maxTargetUsers {
		return Command{}, fmt.Errorf("target_users must contain 1-%d users", maxTargetUsers)
	}
	targetUsers, err := normalizeUsers(*raw.TargetUsers)
	if err != nil {
		return Command{}, err
	}
	workingDirectory, err := validateDirectory(raw.WorkingDirectory)
	if err != nil {
		return Command{}, err
	}
	if raw.TimeoutSeconds < 1 || raw.TimeoutSeconds > maxTimeoutSeconds {
		return Command{}, fmt.Errorf("timeout_seconds must be between 1 and %d", maxTimeoutSeconds)
	}
	if raw.MaxOutputBytes == nil || *raw.MaxOutputBytes < 0 || *raw.MaxOutputBytes > maxOutputBytes {
		return Command{}, fmt.Errorf("max_output_bytes must be between 0 and %d", maxOutputBytes)
	}
	if err := validateEnvironment(raw.Environment); err != nil {
		return Command{}, err
	}
	if err := validateDisplayText(raw.Description, 256, "description"); err != nil {
		return Command{}, err
	}
	risk := raw.Risk
	if risk == "" {
		risk = defaultCommandRisk
	}
	if risk != "low" && risk != "medium" && risk != "high" {
		return Command{}, errors.New("risk must be low, medium, or high")
	}
	return Command{ID: raw.ID, Executable: executable, Arguments: arguments, TargetUsers: targetUsers,
		WorkingDirectory: workingDirectory, TimeoutSeconds: raw.TimeoutSeconds, MaxOutputBytes: *raw.MaxOutputBytes,
		Environment: cloneMap(raw.Environment), Description: raw.Description, Risk: risk}, nil
}

func validateArguments(arguments []Argument) error {
	slots := map[string]bool{}
	for index, argument := range arguments {
		if argument.Literal != nil {
			if argument.Slot != "" || argument.Type != "" || argument.Minimum != nil || argument.Maximum != nil || len(argument.Values) > 0 || len(argument.Roots) > 0 || argument.MustExist || argument.FileType != "" {
				return fmt.Errorf("arguments[%d]: literal argument contains slot fields", index)
			}
			if err := validateValue(*argument.Literal, "literal"); err != nil {
				return fmt.Errorf("arguments[%d]: %w", index, err)
			}
			continue
		}
		if !slotPattern.MatchString(argument.Slot) || slots[argument.Slot] {
			return fmt.Errorf("arguments[%d]: slot is invalid or duplicated", index)
		}
		slots[argument.Slot] = true
		if err := validateSlot(argument); err != nil {
			return fmt.Errorf("arguments[%d]: %w", index, err)
		}
	}
	return nil
}

func validateSlot(argument Argument) error {
	switch argument.Type {
	case "integer":
		if argument.Minimum == nil || argument.Maximum == nil || *argument.Minimum > *argument.Maximum || len(argument.Values) > 0 || len(argument.Roots) > 0 || argument.MustExist || argument.FileType != "" {
			return errors.New("integer slot requires only a valid minimum and maximum")
		}
	case "enum":
		if argument.Minimum != nil || argument.Maximum != nil || len(argument.Values) == 0 || len(argument.Values) > 256 || len(argument.Roots) > 0 || argument.MustExist || argument.FileType != "" {
			return errors.New("enum slot requires only bounded values")
		}
		seen := map[string]bool{}
		for _, value := range argument.Values {
			if validateValue(value, "enum value") != nil || seen[value] {
				return errors.New("enum values must be unique, bounded, non-empty strings")
			}
			seen[value] = true
		}
	case "path_beneath":
		if argument.Minimum != nil || argument.Maximum != nil || len(argument.Values) > 0 || len(argument.Roots) == 0 || len(argument.Roots) > 16 || (argument.FileType != "regular" && argument.FileType != "directory") {
			return errors.New("path_beneath slot requires roots and a regular or directory file_type")
		}
		for _, root := range argument.Roots {
			if _, err := validateDirectory(root); err != nil {
				return fmt.Errorf("invalid path root: %w", err)
			}
		}
	default:
		return errors.New("slot type must be integer, enum, or path_beneath")
	}
	return nil
}

func resolveArgument(spec Argument, raw json.RawMessage) (string, error) {
	if err := strictjson.RejectDuplicateKeys(raw); err != nil {
		return "", errors.New("invalid JSON value")
	}
	switch spec.Type {
	case "integer":
		value, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil || value < *spec.Minimum || value > *spec.Maximum {
			return "", fmt.Errorf("must be an integer between %d and %d", *spec.Minimum, *spec.Maximum)
		}
		return strconv.FormatInt(value, 10), nil
	case "enum":
		var value string
		if err := json.Unmarshal(raw, &value); err != nil || !slices.Contains(spec.Values, value) {
			return "", errors.New("must be one of the declared enum values")
		}
		return value, nil
	case "path_beneath":
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", errors.New("must be a path string")
		}
		return resolvePath(spec, value)
	default:
		return "", errors.New("unsupported argument type")
	}
}

func resolvePath(spec Argument, value string) (string, error) {
	if !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return "", errors.New("path must be absolute and normalized")
	}
	resolved, err := filepath.EvalSymlinks(value)
	if err != nil {
		if spec.MustExist {
			return "", errors.New("path must exist")
		}
		resolved, err = resolveMissingPath(value)
		if err != nil {
			return "", err
		}
	}
	inside := false
	for _, root := range spec.Roots {
		resolvedRoot, rootErr := filepath.EvalSymlinks(root)
		if rootErr == nil && pathBeneath(resolvedRoot, resolved) {
			inside = true
			break
		}
	}
	if !inside {
		return "", errors.New("path escapes declared roots")
	}
	if info, statErr := os.Stat(resolved); statErr == nil {
		if spec.FileType == "regular" && !info.Mode().IsRegular() {
			return "", errors.New("path is not a regular file")
		}
		if spec.FileType == "directory" && !info.IsDir() {
			return "", errors.New("path is not a directory")
		}
	} else if spec.MustExist {
		return "", errors.New("path must exist")
	}
	return resolved, nil
}

func resolveMissingPath(value string) (string, error) {
	current := value
	var tail []string
	for {
		if _, err := os.Lstat(current); err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", errors.New("path cannot be resolved safely")
			}
			for index := len(tail) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, tail[index])
			}
			return resolved, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", errors.New("path cannot be resolved safely")
		}
		tail = append(tail, filepath.Base(current))
		current = parent
	}
}

func pathBeneath(root, value string) bool {
	relative, err := filepath.Rel(root, value)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func validateExecutable(value string) (string, error) {
	if !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return "", errors.New("executable must be absolute and normalized")
	}
	if shellEquivalent(filepath.Base(value)) {
		return "", errors.New("executable must not be a shell or generic launcher")
	}
	info, err := os.Lstat(value)
	if err != nil {
		return "", fmt.Errorf("stat executable: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", errors.New("executable must be a non-symlink executable regular file")
	}
	return value, nil
}

func shellEquivalent(base string) bool {
	switch base {
	case "ash", "bash", "busybox", "csh", "dash", "env", "fish", "hush", "ksh", "pwsh", "sh", "su", "sudo", "tcsh", "zsh":
		return true
	default:
		return false
	}
}

func validateDirectory(value string) (string, error) {
	if !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return "", errors.New("working directory must be absolute and normalized")
	}
	info, err := os.Lstat(value)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("working directory must be an existing non-symlink directory")
	}
	return value, nil
}

func normalizeUsers(values []string) ([]string, error) {
	seen := map[string]bool{}
	users := append([]string(nil), values...)
	for _, value := range users {
		if !userPattern.MatchString(value) || seen[value] {
			return nil, errors.New("target_users must contain unique non-numeric Unix user names")
		}
		seen[value] = true
	}
	slices.Sort(users)
	return users, nil
}

func validateEnvironment(environment map[string]string) error {
	for key, value := range environment {
		if !envPattern.MatchString(key) || unsafeEnvironmentName(key) {
			return fmt.Errorf("environment name %q is unsafe", key)
		}
		if err := validateValue(value, "environment value"); err != nil {
			return err
		}
	}
	return nil
}

func unsafeEnvironmentName(value string) bool {
	return value == "PATH" || value == "IFS" || value == "ENV" || value == "BASH_ENV" || value == "ZDOTDIR" ||
		strings.HasPrefix(value, "LD_") || strings.HasPrefix(value, "DYLD_")
}

func validateValue(value string, label string) error {
	if value == "" || len(value) > maxStringBytes || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("%s must be a bounded non-empty string without control characters", label)
	}
	return nil
}

func validateDisplayText(value string, maximum int, label string) error {
	if len(value) > maximum || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("%s is too long or contains control characters", label)
	}
	return nil
}

func requireEOF(decoder *json.Decoder) error {
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("parse sudo catalog: trailing JSON content")
	}
	return nil
}

func cloneCommand(command Command) Command {
	command.Arguments = append([]Argument(nil), command.Arguments...)
	for index := range command.Arguments {
		argument := &command.Arguments[index]
		argument.Values = append([]string(nil), argument.Values...)
		argument.Roots = append([]string(nil), argument.Roots...)
		if argument.Literal != nil {
			value := *argument.Literal
			argument.Literal = &value
		}
		if argument.Minimum != nil {
			value := *argument.Minimum
			argument.Minimum = &value
		}
		if argument.Maximum != nil {
			value := *argument.Maximum
			argument.Maximum = &value
		}
	}
	command.TargetUsers = append([]string(nil), command.TargetUsers...)
	command.Environment = cloneMap(command.Environment)
	return command
}

func cloneMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}
