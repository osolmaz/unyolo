package operations

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
)

type sandboxClient interface {
	WhoAmI(context.Context) (hubclient.Identity, error)
	SandboxState(context.Context, hubclient.SandboxRef) (hubclient.SandboxState, error)
	ListSandboxPool(context.Context, hubclient.SandboxPoolRef) ([]hubclient.SandboxState, error)
	ListSandboxesByOperation(context.Context, string, string) ([]hubclient.SandboxState, error)
	CreateSandbox(context.Context, hubclient.SandboxCreateSpec) (hubclient.SandboxState, error)
	CreateSandboxPoolHost(context.Context, hubclient.SandboxPoolSpec) (hubclient.SandboxState, error)
	CreateSandboxInPool(context.Context, hubclient.SandboxRef, map[string]string, *int) (hubclient.SandboxRef, error)
	DeleteSandbox(context.Context, hubclient.SandboxRef) error
	CancelSandboxJob(context.Context, hubclient.SandboxRef) error
	RunSandboxCommand(context.Context, hubclient.SandboxRef, hubclient.SandboxCommand) (hubclient.SandboxCommandResult, error)
	SandboxFileStat(context.Context, hubclient.SandboxRef, string) (hubclient.SandboxFileInfo, error)
	WriteSandboxFile(context.Context, hubclient.SandboxRef, string, string, []byte) error
	MakeSandboxDirectory(context.Context, hubclient.SandboxRef, string) error
	DeleteSandboxFile(context.Context, hubclient.SandboxRef, string, bool) error
	SandboxProcesses(context.Context, hubclient.SandboxRef) ([]hubclient.SandboxProcess, error)
	KillSandboxProcess(context.Context, hubclient.SandboxRef, int) error
}

type sandboxAdapter struct {
	descriptor opcatalog.Descriptor
	client     sandboxClient
	store      sealedPayloadStore
}

type sandboxTarget struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name,omitempty"`
	Pool      string `json:"pool,omitempty"`
	JobID     string `json:"job_id,omitempty"`
	LocalID   string `json:"local_id,omitempty"`
}

type sandboxCreatePublic struct {
	Image              string                  `json:"image,omitempty"`
	Flavor             string                  `json:"flavor,omitempty"`
	IdleTimeoutSeconds *int                    `json:"idle_timeout_seconds,omitempty"`
	Environment        map[string]string       `json:"environment,omitempty"`
	Volumes            []sandboxVolumeArgument `json:"volumes,omitempty"`
}

type sandboxVolumeArgument struct {
	Type      string `json:"type"`
	Source    string `json:"source"`
	MountPath string `json:"mount_path"`
	Revision  string `json:"revision,omitempty"`
	ReadOnly  *bool  `json:"read_only,omitempty"`
	Path      string `json:"path,omitempty"`
}

type sandboxCreateSecret struct {
	Secrets map[string]string `json:"secrets"`
}

type sandboxPoolCreatePublic struct {
	Image              string `json:"image"`
	Flavor             string `json:"flavor"`
	SandboxesPerHost   int    `json:"sandboxes_per_host"`
	WarmUp             int    `json:"warm_up"`
	MaxHosts           int    `json:"max_hosts"`
	IdleTimeoutSeconds *int   `json:"idle_timeout_seconds,omitempty"`
}

type sandboxCommandArguments struct {
	Argv           []string          `json:"argv,omitempty"`
	ShellCommand   string            `json:"shell_command,omitempty"`
	Environment    map[string]string `json:"environment,omitempty"`
	WorkingDir     string            `json:"working_dir,omitempty"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty"`
	Stdin          string            `json:"stdin,omitempty"`
	Background     bool              `json:"background,omitempty"`
	MaxOutputBytes int               `json:"max_output_bytes"`
}

type sandboxFileWriteArguments struct {
	Path          string `json:"path"`
	ContentBase64 string `json:"content_base64"`
	Mode          string `json:"mode,omitempty"`
}

type sandboxFileDeleteArguments struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive,omitempty"`
}

type sandboxFileMkdirArguments struct {
	Path string `json:"path"`
}

type sandboxPoolWarmArguments struct {
	NumHosts int `json:"num_hosts"`
}

type sandboxProcessKillArguments struct {
	PID int `json:"pid"`
}

type sandboxPreconditions struct {
	CredentialIdentity string                `json:"credential_identity"`
	StateDigest        string                `json:"state_digest,omitempty"`
	ResourceDigest     string                `json:"resource_digest,omitempty"`
	ResourceAbsent     bool                  `json:"resource_absent,omitempty"`
	OperationID        string                `json:"operation_id,omitempty"`
	PoolDigest         string                `json:"pool_digest,omitempty"`
	PoolConfig         *sandboxPoolConfig    `json:"pool_config,omitempty"`
	Host               *hubclient.SandboxRef `json:"host,omitempty"`
	ExpectedHosts      int                   `json:"expected_hosts,omitempty"`
	CreatedHosts       int                   `json:"created_hosts,omitempty"`
}

type sandboxPoolConfig struct {
	Image              string `json:"image"`
	Flavor             string `json:"flavor"`
	SandboxesPerHost   int    `json:"sandboxes_per_host"`
	MaxHosts           int    `json:"max_hosts"`
	IdleTimeoutSeconds *int   `json:"idle_timeout_seconds,omitempty"`
}

var sandboxOperations = []string{
	"sandbox.command.run", "sandbox.create", "sandbox.delete", "sandbox.file.delete", "sandbox.file.mkdir",
	"sandbox.file.write", "sandbox.pool.create", "sandbox.pool.delete", "sandbox.pool.warm", "sandbox.process.kill",
}

func NewSandboxAdapters(client sandboxClient, store sealedPayloadStore) ([]Adapter, error) {
	if client == nil || store == nil {
		return nil, errors.New("hugging face sandbox operation dependencies are required")
	}
	adapters := make([]Adapter, 0, len(sandboxOperations))
	for _, name := range sandboxOperations {
		descriptor, found := opcatalog.ByName(name)
		if !found || descriptor.AuthorizationMode != opcatalog.ModeExecution {
			return nil, fmt.Errorf("sandbox operation %q is absent from the execution catalog", name)
		}
		adapters = append(adapters, &sandboxAdapter{descriptor: descriptor, client: client, store: store})
	}
	return adapters, nil
}

func (a *sandboxAdapter) Descriptor() opcatalog.Descriptor { return a.descriptor }

func (a *sandboxAdapter) Decode(targetRaw, argumentsRaw json.RawMessage) (Input, error) {
	target, err := a.decodeTarget(targetRaw)
	if err != nil {
		return Input{}, err
	}
	arguments, err := a.decodeArguments(target, argumentsRaw)
	if err != nil {
		return Input{}, err
	}
	canonicalTarget, _ := canonical(target)
	canonicalArguments, _ := canonical(arguments)
	return Input{Target: canonicalTarget, Arguments: canonicalArguments}, nil
}

func (a *sandboxAdapter) ValidateClient(input Input, client string) error {
	if !a.descriptor.Sealed {
		return nil
	}
	arguments, err := decodeSealedArguments(input.Arguments)
	if err != nil || arguments.SealedPayload == nil {
		return err
	}
	if arguments.SealedPayload.Owner != client || arguments.SealedPayload.Purpose != a.descriptor.Name {
		return errors.New("sealed payload does not belong to this client and operation")
	}
	payload, err := a.store.Get(*arguments.SealedPayload)
	zero(payload)
	return err
}

//nolint:cyclop // Resource-kind decoding is explicit and tracked by the exact HF CRAP baseline.
func (a *sandboxAdapter) decodeTarget(raw json.RawMessage) (sandboxTarget, error) {
	var target sandboxTarget
	if err := decodeClosed(raw, &target, maxTargetBytes); err != nil || !hubclient.ValidNamespaceSegment(target.Namespace) {
		return sandboxTarget{}, errors.New("sandbox target is invalid")
	}
	switch a.descriptor.Name {
	case "sandbox.create":
		if target.Kind != "sandbox" || !hubclient.ValidNamespaceSegment(target.Name) || target.JobID != "" || target.LocalID != "" ||
			target.Pool != "" && !hubclient.ValidNamespaceSegment(target.Pool) {
			return sandboxTarget{}, errors.New("sandbox create target is invalid")
		}
	case "sandbox.pool.create", "sandbox.pool.delete", "sandbox.pool.warm":
		if target.Kind != "sandbox_pool" || !hubclient.ValidNamespaceSegment(target.Name) || target.Pool != "" || target.JobID != "" || target.LocalID != "" {
			return sandboxTarget{}, errors.New("sandbox pool target is invalid")
		}
	default:
		ref := target.ref()
		if target.Kind != "sandbox" || target.Name != "" || target.Pool != "" || ref.Validate() != nil {
			return sandboxTarget{}, errors.New("sandbox target is invalid")
		}
	}
	return target, nil
}

//nolint:cyclop // Sandbox operation dispatch is explicit and tracked by the exact HF CRAP baseline.
func (a *sandboxAdapter) decodeArguments(target sandboxTarget, raw json.RawMessage) (any, error) {
	switch a.descriptor.Name {
	case "sandbox.create":
		return a.decodeSealedPublic(raw, func(public json.RawMessage) (any, error) {
			var value sandboxCreatePublic
			if err := decodeClosed(public, &value, maxArgumentsBytes); err != nil || validateSandboxCreatePublic(target, value) != nil {
				return nil, errors.New("sandbox create arguments are invalid")
			}
			return value, nil
		})
	case "sandbox.pool.create":
		var value sandboxPoolCreatePublic
		if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || validateSandboxPoolCreatePublic(value) != nil {
			return nil, errors.New("sandbox pool create arguments are invalid")
		}
		return value, nil
	case "sandbox.command.run":
		var value sandboxCommandArguments
		if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || validateSandboxCommandArguments(value) != nil {
			return nil, errors.New("sandbox command arguments are invalid")
		}
		return value, nil
	case "sandbox.file.write":
		var value sandboxFileWriteArguments
		if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || validateSandboxFileWrite(value) != nil {
			return nil, errors.New("sandbox file write arguments are invalid")
		}
		return value, nil
	case "sandbox.file.delete":
		var value sandboxFileDeleteArguments
		if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || !validSandboxOperationPath(value.Path) {
			return nil, errors.New("sandbox file delete arguments are invalid")
		}
		return value, nil
	case "sandbox.file.mkdir":
		var value sandboxFileMkdirArguments
		if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || !validSandboxOperationPath(value.Path) {
			return nil, errors.New("sandbox directory arguments are invalid")
		}
		return value, nil
	case "sandbox.pool.warm":
		var value sandboxPoolWarmArguments
		if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || value.NumHosts < 1 || value.NumHosts > 32 {
			return nil, errors.New("sandbox pool warm arguments are invalid")
		}
		return value, nil
	case "sandbox.process.kill":
		var value sandboxProcessKillArguments
		if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || value.PID < 1 {
			return nil, errors.New("sandbox process arguments are invalid")
		}
		return value, nil
	case "sandbox.delete", "sandbox.pool.delete":
		var value emptyArguments
		if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil {
			return nil, errors.New("sandbox operation arguments must be empty")
		}
		return value, nil
	default:
		return nil, errors.New("sandbox operation is not implemented")
	}
}

func (a *sandboxAdapter) decodeSealedPublic(raw json.RawMessage, decode func(json.RawMessage) (any, error)) (sealedBoundArguments, error) {
	arguments, err := decodeSealedArguments(raw)
	if err != nil {
		return sealedBoundArguments{}, err
	}
	value, err := decode(arguments.Public)
	if err != nil {
		return sealedBoundArguments{}, err
	}
	arguments.Public, err = canonical(value)
	return arguments, err
}

//nolint:cyclop // Sandbox creation bounds are explicit and tracked by the exact HF CRAP baseline.
func validateSandboxCreatePublic(target sandboxTarget, value sandboxCreatePublic) error {
	if value.IdleTimeoutSeconds != nil && (*value.IdleTimeoutSeconds < 30 || *value.IdleTimeoutSeconds > hubclient.SandboxMaxLifetimeSecs) ||
		len(value.Environment) > 128 || len(value.Volumes) > 32 {
		return errors.New("sandbox create bounds are invalid")
	}
	if target.Pool == "" && (value.Image == "" || value.Flavor == "") {
		return errors.New("dedicated sandbox image and flavor are required")
	}
	if target.Pool == "" && (!hubclient.ValidSandboxImage(value.Image) || !hubclient.ValidJobHardware(value.Flavor)) {
		return errors.New("dedicated sandbox image or flavor is invalid")
	}
	if target.Pool != "" && (value.Image != "" || value.Flavor != "" || len(value.Volumes) != 0) {
		return errors.New("pooled sandbox inherits its host image, flavor, and volumes")
	}
	for key, item := range value.Environment {
		if !validEnvironmentEntry(key, item) || key == "HF_TOKEN" {
			return errors.New("sandbox environment is invalid")
		}
	}
	for _, volume := range value.Volumes {
		if hubclient.ValidateSandboxVolume(volume.hubVolume()) != nil {
			return errors.New("sandbox volume is invalid")
		}
	}
	return nil
}

//nolint:cyclop // Pool creation bounds are explicit and tracked by the exact HF CRAP baseline.
func validateSandboxPoolCreatePublic(value sandboxPoolCreatePublic) error {
	if !hubclient.ValidSandboxImage(value.Image) || !hubclient.ValidJobHardware(value.Flavor) || value.SandboxesPerHost < 1 || value.SandboxesPerHost > 500 ||
		value.WarmUp < 1 || value.MaxHosts < value.WarmUp || value.MaxHosts > 32 ||
		value.IdleTimeoutSeconds != nil && (*value.IdleTimeoutSeconds < 30 || *value.IdleTimeoutSeconds > hubclient.SandboxMaxLifetimeSecs) {
		return errors.New("sandbox pool configuration is invalid")
	}
	return nil
}

//nolint:cyclop // Command argument bounds are explicit and tracked by the exact HF CRAP baseline.
func validateSandboxCommandArguments(value sandboxCommandArguments) error {
	command := value.command()
	if (len(value.Argv) == 0) == (value.ShellCommand == "") || command.MaxOutputBytes < 1 || command.MaxOutputBytes > hubclient.SandboxMaxCommandOutput ||
		value.TimeoutSeconds < 0 || value.TimeoutSeconds > 3600 || value.Background && (value.TimeoutSeconds != 0 || value.Stdin != "") ||
		len(value.Stdin) > 256*1024 || value.WorkingDir != "" && !validSandboxOperationPath(value.WorkingDir) || len(value.Environment) > 128 {
		return errors.New("sandbox command bounds are invalid")
	}
	commandBytes := len(value.ShellCommand)
	for key, item := range value.Environment {
		if !validEnvironmentEntry(key, item) {
			return errors.New("sandbox command environment is invalid")
		}
	}
	for _, argument := range value.Argv {
		if argument == "" || len(argument) > 64*1024 || strings.ContainsRune(argument, 0) {
			return errors.New("sandbox argv is invalid")
		}
		commandBytes += len(argument) + 1
	}
	if commandBytes > 1200 {
		return errors.New("sandbox command is too large for exact operator presentation")
	}
	return nil
}

func validateSandboxFileWrite(value sandboxFileWriteArguments) error {
	content, err := base64.StdEncoding.Strict().DecodeString(value.ContentBase64)
	if err != nil || len(content) > 700*1024 || !validSandboxOperationPath(value.Path) || !hubclient.ValidSandboxFileMode(value.Mode) {
		return errors.New("sandbox file write is invalid")
	}
	return nil
}

func validSandboxOperationPath(value string) bool {
	return value != "" && len(value) <= 4096 && !strings.ContainsRune(value, 0)
}

//nolint:cyclop // Environment syntax checks are explicit and tracked by the exact HF CRAP baseline.
func validEnvironmentEntry(key, value string) bool {
	if key == "" || len(key) > 128 || strings.HasPrefix(key, "SBX_") || len(value) > 64*1024 || strings.ContainsRune(value, 0) {
		return false
	}
	for index, character := range key {
		letter := character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z'
		digit := character >= '0' && character <= '9'
		if index == 0 && digit || character != '_' && !letter && !digit {
			return false
		}
	}
	return true
}

func (target sandboxTarget) ref() hubclient.SandboxRef {
	return hubclient.SandboxRef{Namespace: target.Namespace, JobID: target.JobID, LocalID: target.LocalID}
}

func (target sandboxTarget) poolRef() hubclient.SandboxPoolRef {
	name := target.Name
	if target.Pool != "" {
		name = target.Pool
	}
	return hubclient.SandboxPoolRef{Namespace: target.Namespace, Name: name}
}

func (value sandboxCommandArguments) command() hubclient.SandboxCommand {
	return hubclient.SandboxCommand{Argv: value.Argv, ShellCommand: value.ShellCommand, Environment: value.Environment,
		WorkingDir: value.WorkingDir, TimeoutSeconds: value.TimeoutSeconds, Stdin: value.Stdin,
		Background: value.Background, MaxOutputBytes: value.MaxOutputBytes}
}

func (value sandboxVolumeArgument) hubVolume() hubclient.SandboxVolume {
	return hubclient.SandboxVolume{Type: value.Type, Source: value.Source, MountPath: value.MountPath,
		Revision: value.Revision, ReadOnly: value.ReadOnly, Path: value.Path}
}

func (value sandboxCreatePublic) hubVolumes() []hubclient.SandboxVolume {
	volumes := make([]hubclient.SandboxVolume, len(value.Volumes))
	for index := range value.Volumes {
		volumes[index] = value.Volumes[index].hubVolume()
	}
	return volumes
}

func newOperationMarker() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("generate sandbox operation marker")
	}
	return hex.EncodeToString(value), nil
}

//nolint:cyclop // Operation presentation dispatch is explicit and tracked by the exact HF CRAP baseline.
func (a *sandboxAdapter) presentationAndPolicy(target sandboxTarget, raw json.RawMessage) (agentv1.Presentation, hfpolicy.Request) {
	name := target.Name
	if name == "" {
		name = target.ref().ID()
	}
	request := hfpolicy.Request{Operation: hfpolicy.Operation(a.descriptor.Name), Target: hfpolicy.Target{
		Kind: hfpolicy.TargetKind(a.descriptor.TargetKind), Owner: target.Namespace, Name: name,
	}, Attrs: map[string]any{}}
	summary := strings.ReplaceAll(a.descriptor.Name, ".", " ") + " on " + target.Namespace + "/" + name
	switch a.descriptor.Name {
	case "sandbox.create":
		var arguments sandboxCreatePublic
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		request.Attrs["pool"] = target.Pool
		request.Attrs["flavor"] = arguments.Flavor
		summary = fmt.Sprintf("Create sandbox %s/%s with image %s and flavor %s", target.Namespace, target.Name, arguments.Image, arguments.Flavor)
		if target.Pool != "" {
			summary = fmt.Sprintf("Create sandbox %s/%s in pool %s", target.Namespace, target.Name, target.Pool)
		}
	case "sandbox.pool.create":
		var arguments sandboxPoolCreatePublic
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		request.Attrs["flavor"] = arguments.Flavor
		request.Attrs["warm_up"] = int64(arguments.WarmUp)
		request.Attrs["max_hosts"] = int64(arguments.MaxHosts)
		summary = fmt.Sprintf("Create sandbox pool %s/%s with %d warm host(s), at most %d host(s), flavor %s", target.Namespace, target.Name, arguments.WarmUp, arguments.MaxHosts, arguments.Flavor)
	case "sandbox.command.run":
		var arguments sandboxCommandArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		request.Attrs["shell"] = arguments.ShellCommand != ""
		request.Attrs["background"] = arguments.Background
		request.Attrs["command_digest"] = digest([]byte(strings.Join(arguments.Argv, "\x00") + arguments.ShellCommand))
		command := ""
		if arguments.ShellCommand != "" {
			encoded, _ := json.Marshal(arguments.ShellCommand)
			command = string(encoded)
		} else {
			encoded, _ := json.Marshal(arguments.Argv)
			command = string(encoded)
		}
		summary = fmt.Sprintf("Run %s in sandbox %s/%s", command, target.Namespace, name)
	case "sandbox.file.write":
		var arguments sandboxFileWriteArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		request.Attrs["path"] = arguments.Path
		request.Attrs["content_digest"] = digest(decodeSandboxContent(arguments.ContentBase64))
		summary = fmt.Sprintf("Write %s in sandbox %s/%s (content digest %s)", arguments.Path, target.Namespace, name, request.Attrs["content_digest"].(string)[:12])
	case "sandbox.file.delete":
		var arguments sandboxFileDeleteArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		request.Attrs["path"] = arguments.Path
		request.Attrs["recursive"] = arguments.Recursive
		summary = fmt.Sprintf("Delete %s from sandbox %s/%s (recursive: %t)", arguments.Path, target.Namespace, name, arguments.Recursive)
	case "sandbox.file.mkdir":
		var arguments sandboxFileMkdirArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		request.Attrs["path"] = arguments.Path
		summary = fmt.Sprintf("Create directory %s in sandbox %s/%s", arguments.Path, target.Namespace, name)
	case "sandbox.process.kill":
		var arguments sandboxProcessKillArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		request.Attrs["pid"] = int64(arguments.PID)
		summary = fmt.Sprintf("Kill process %d in sandbox %s/%s", arguments.PID, target.Namespace, name)
	case "sandbox.pool.warm":
		var arguments sandboxPoolWarmArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		request.Attrs["num_hosts"] = int64(arguments.NumHosts)
		summary = fmt.Sprintf("Warm sandbox pool %s/%s to %d host(s)", target.Namespace, target.Name, arguments.NumHosts)
	case "sandbox.pool.delete":
		summary = fmt.Sprintf("Delete sandbox pool %s/%s and cancel all active hosts", target.Namespace, target.Name)
	case "sandbox.delete":
		summary = fmt.Sprintf("Delete sandbox %s/%s", target.Namespace, name)
	}
	return agentv1.Presentation{Title: strings.ReplaceAll(a.descriptor.Name, ".", " "), Summary: summary}, request
}

var _ ClientBoundAdapter = (*sandboxAdapter)(nil)
var _ PlanCleaner = (*sandboxAdapter)(nil)
