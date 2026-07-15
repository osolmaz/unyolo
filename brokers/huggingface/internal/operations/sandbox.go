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
	"sandbox.create", "sandbox.delete", "sandbox.file.delete", "sandbox.file.mkdir",
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

func (a *sandboxAdapter) ValidateClient(input Input, client, requestKey string) error {
	if !a.descriptor.Sealed {
		return nil
	}
	arguments, err := decodeSealedArguments(input.Arguments)
	if err != nil || arguments.SealedPayload == nil {
		return err
	}
	if err := validateSealedReference(arguments.SealedPayload, client, a.descriptor.Name, requestKey); err != nil {
		return err
	}
	return a.store.Validate(*arguments.SealedPayload)
}

func (a *sandboxAdapter) decodeTarget(raw json.RawMessage) (sandboxTarget, error) {
	var target sandboxTarget
	if err := decodeClosed(raw, &target, maxTargetBytes); err != nil || !hubclient.ValidNamespaceSegment(target.Namespace) {
		return sandboxTarget{}, errors.New("sandbox target is invalid")
	}
	validate, message := sandboxTargetValidation(a.descriptor.Name)
	if !validate(target) {
		return sandboxTarget{}, errors.New(message)
	}
	return target, nil
}

func sandboxTargetValidation(operation string) (func(sandboxTarget) bool, string) {
	if operation == "sandbox.create" {
		return validSandboxCreateTarget, "sandbox create target is invalid"
	}
	if strings.HasPrefix(operation, "sandbox.pool.") {
		return validSandboxPoolTarget, "sandbox pool target is invalid"
	}
	return validExistingSandboxTarget, "sandbox target is invalid"
}

func validSandboxCreateTarget(target sandboxTarget) bool {
	return target.Kind == "sandbox" && hubclient.ValidNamespaceSegment(target.Name) && target.JobID == "" && target.LocalID == "" &&
		(target.Pool == "" || hubclient.ValidNamespaceSegment(target.Pool))
}

func validSandboxPoolTarget(target sandboxTarget) bool {
	return target.Kind == "sandbox_pool" && hubclient.ValidNamespaceSegment(target.Name) && target.Pool == "" && target.JobID == "" && target.LocalID == ""
}

func validExistingSandboxTarget(target sandboxTarget) bool {
	return target.Kind == "sandbox" && target.Name == "" && target.Pool == "" && target.ref().Validate() == nil
}

func (a *sandboxAdapter) decodeArguments(target sandboxTarget, raw json.RawMessage) (any, error) {
	decode, found := sandboxArgumentDecoders[a.descriptor.Name]
	if !found {
		return nil, errors.New("sandbox operation is not implemented")
	}
	return decode(a, target, raw)
}

var sandboxArgumentDecoders = map[string]func(*sandboxAdapter, sandboxTarget, json.RawMessage) (any, error){
	"sandbox.create":       decodeSandboxCreateArguments,
	"sandbox.pool.create":  sandboxArgumentDecoder(func(value sandboxPoolCreatePublic) bool { return validateSandboxPoolCreatePublic(value) == nil }, "sandbox pool create arguments are invalid"),
	"sandbox.file.write":   sandboxArgumentDecoder(func(value sandboxFileWriteArguments) bool { return validateSandboxFileWrite(value) == nil }, "sandbox file write arguments are invalid"),
	"sandbox.file.delete":  sandboxArgumentDecoder(func(value sandboxFileDeleteArguments) bool { return validSandboxOperationPath(value.Path) }, "sandbox file delete arguments are invalid"),
	"sandbox.file.mkdir":   sandboxArgumentDecoder(func(value sandboxFileMkdirArguments) bool { return validSandboxOperationPath(value.Path) }, "sandbox directory arguments are invalid"),
	"sandbox.pool.warm":    decodeSandboxPoolWarmArguments,
	"sandbox.process.kill": decodeSandboxProcessKillArguments,
	"sandbox.delete":       decodeEmptySandboxArguments,
	"sandbox.pool.delete":  decodeEmptySandboxArguments,
}

func decodeSandboxCreateArguments(a *sandboxAdapter, target sandboxTarget, raw json.RawMessage) (any, error) {
	return a.decodeSealedPublic(raw, func(public json.RawMessage) (any, error) {
		var value sandboxCreatePublic
		if err := decodeClosed(public, &value, maxArgumentsBytes); err != nil || validateSandboxCreatePublic(target, value) != nil {
			return nil, errors.New("sandbox create arguments are invalid")
		}
		return value, nil
	})
}

func sandboxArgumentDecoder[T any](valid func(T) bool, message string) func(*sandboxAdapter, sandboxTarget, json.RawMessage) (any, error) {
	return func(_ *sandboxAdapter, _ sandboxTarget, raw json.RawMessage) (any, error) {
		return decodeValidatedArguments(raw, valid, message)
	}
}

func decodeSandboxPoolWarmArguments(_ *sandboxAdapter, _ sandboxTarget, raw json.RawMessage) (any, error) {
	var value sandboxPoolWarmArguments
	if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || value.NumHosts < 1 || value.NumHosts > 32 {
		return nil, errors.New("sandbox pool warm arguments are invalid")
	}
	return value, nil
}

func decodeSandboxProcessKillArguments(_ *sandboxAdapter, _ sandboxTarget, raw json.RawMessage) (any, error) {
	var value sandboxProcessKillArguments
	if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil || value.PID < 1 {
		return nil, errors.New("sandbox process arguments are invalid")
	}
	return value, nil
}

func decodeEmptySandboxArguments(_ *sandboxAdapter, _ sandboxTarget, raw json.RawMessage) (any, error) {
	var value emptyArguments
	if err := decodeClosed(raw, &value, maxArgumentsBytes); err != nil {
		return nil, errors.New("sandbox operation arguments must be empty")
	}
	return value, nil
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

func validateSandboxCreatePublic(target sandboxTarget, value sandboxCreatePublic) error {
	if sandboxCreateBoundsInvalid(value) {
		return errors.New("sandbox create bounds are invalid")
	}
	if dedicatedSandboxMissingImageOrFlavor(target, value) {
		return errors.New("dedicated sandbox image and flavor are required")
	}
	if dedicatedSandboxImageOrFlavorInvalid(target, value) {
		return errors.New("dedicated sandbox image or flavor is invalid")
	}
	if pooledSandboxOverridesHost(target, value) {
		return errors.New("pooled sandbox inherits its host image, flavor, and volumes")
	}
	if !validSandboxCreateEnvironment(value.Environment) {
		return errors.New("sandbox environment is invalid")
	}
	if !validSandboxCreateVolumes(value.Volumes) {
		return errors.New("sandbox volume is invalid")
	}
	return nil
}

func sandboxCreateBoundsInvalid(value sandboxCreatePublic) bool {
	return value.IdleTimeoutSeconds != nil && (*value.IdleTimeoutSeconds < 30 || *value.IdleTimeoutSeconds > hubclient.SandboxMaxLifetimeSecs) ||
		len(value.Environment) > 128 || len(value.Volumes) > 32
}

func dedicatedSandboxMissingImageOrFlavor(target sandboxTarget, value sandboxCreatePublic) bool {
	return target.Pool == "" && (value.Image == "" || value.Flavor == "")
}

func dedicatedSandboxImageOrFlavorInvalid(target sandboxTarget, value sandboxCreatePublic) bool {
	return target.Pool == "" && (!hubclient.ValidSandboxImage(value.Image) || !hubclient.ValidJobHardware(value.Flavor))
}

func pooledSandboxOverridesHost(target sandboxTarget, value sandboxCreatePublic) bool {
	return target.Pool != "" && (value.Image != "" || value.Flavor != "" || len(value.Volumes) != 0)
}

func validSandboxCreateEnvironment(environment map[string]string) bool {
	for key, item := range environment {
		if !validEnvironmentEntry(key, item) || key == "HF_TOKEN" {
			return false
		}
	}
	return true
}

func validSandboxCreateVolumes(volumes []sandboxVolumeArgument) bool {
	for _, volume := range volumes {
		if hubclient.ValidateSandboxVolume(volume.hubVolume()) != nil {
			return false
		}
	}
	return true
}

func validateSandboxPoolCreatePublic(value sandboxPoolCreatePublic) error {
	if sandboxPoolCreateInvalid(value) {
		return errors.New("sandbox pool configuration is invalid")
	}
	return nil
}

func sandboxPoolCreateInvalid(value sandboxPoolCreatePublic) bool {
	return invalidSandboxPoolRuntime(value) || invalidSandboxPoolCapacity(value) || invalidSandboxIdleTimeout(value.IdleTimeoutSeconds)
}

func invalidSandboxPoolRuntime(value sandboxPoolCreatePublic) bool {
	return !hubclient.ValidSandboxImage(value.Image) || !hubclient.ValidJobHardware(value.Flavor)
}

func invalidSandboxPoolCapacity(value sandboxPoolCreatePublic) bool {
	return value.SandboxesPerHost < 1 || value.SandboxesPerHost > 500 || value.WarmUp < 1 || value.MaxHosts < value.WarmUp || value.MaxHosts > 32
}

func invalidSandboxIdleTimeout(value *int) bool {
	return value != nil && (*value < 30 || *value > hubclient.SandboxMaxLifetimeSecs)
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

func validEnvironmentEntry(key, value string) bool {
	if key == "" || len(key) > 128 || strings.HasPrefix(key, "SBX_") || len(value) > 64*1024 || strings.ContainsRune(value, 0) {
		return false
	}
	for index, character := range key {
		if !validEnvironmentKeyCharacter(index, character) {
			return false
		}
	}
	return true
}

func validEnvironmentKeyCharacter(index int, character rune) bool {
	letter := asciiLetter(character)
	digit := asciiDigit(character)
	return (index != 0 || !digit) && (character == '_' || letter || digit)
}

func asciiLetter(character rune) bool {
	return character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z'
}

func asciiDigit(character rune) bool { return character >= '0' && character <= '9' }

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

func (a *sandboxAdapter) presentationAndPolicy(target sandboxTarget, raw json.RawMessage) (agentv1.Presentation, hfpolicy.Request) {
	name := target.Name
	if name == "" {
		name = target.ref().ID()
	}
	request := hfpolicy.Request{Operation: hfpolicy.Operation(a.descriptor.Name), Target: hfpolicy.Target{
		Kind: hfpolicy.TargetKind(a.descriptor.TargetKind), Owner: target.Namespace, Name: name,
	}, Attrs: map[string]any{}}
	summary := strings.ReplaceAll(a.descriptor.Name, ".", " ") + " on " + target.Namespace + "/" + name
	if a.descriptor.Name == "sandbox.create" {
		summary = presentSandboxCreate(target, raw, request.Attrs)
	} else if strings.HasPrefix(a.descriptor.Name, "sandbox.pool.") {
		summary = presentSandboxPool(a.descriptor.Name, target, raw, request.Attrs, summary)
	} else {
		summary = presentSandboxResource(a.descriptor.Name, target.Namespace, name, raw, request.Attrs, summary)
	}
	return agentv1.Presentation{Title: strings.ReplaceAll(a.descriptor.Name, ".", " "), Summary: summary}, request
}

func presentSandboxCreate(target sandboxTarget, raw json.RawMessage, attrs map[string]any) string {
	var arguments sandboxCreatePublic
	_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
	if target.Pool != "" {
		attrs["pool"] = target.Pool
		return fmt.Sprintf("Create sandbox %s/%s in pool %s", target.Namespace, target.Name, target.Pool)
	}
	if arguments.Flavor != "" {
		attrs["flavor"] = arguments.Flavor
	}
	return fmt.Sprintf("Create sandbox %s/%s with image %s and flavor %s", target.Namespace, target.Name, arguments.Image, arguments.Flavor)
}

func presentSandboxPool(operation string, target sandboxTarget, raw json.RawMessage, attrs map[string]any, fallback string) string {
	switch operation {
	case "sandbox.pool.create":
		var arguments sandboxPoolCreatePublic
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		attrs["flavor"], attrs["warm_up"], attrs["max_hosts"] = arguments.Flavor, int64(arguments.WarmUp), int64(arguments.MaxHosts)
		return fmt.Sprintf("Create sandbox pool %s/%s with %d warm host(s), at most %d host(s), flavor %s", target.Namespace, target.Name, arguments.WarmUp, arguments.MaxHosts, arguments.Flavor)
	case "sandbox.pool.warm":
		var arguments sandboxPoolWarmArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		attrs["num_hosts"] = int64(arguments.NumHosts)
		return fmt.Sprintf("Warm sandbox pool %s/%s to %d host(s)", target.Namespace, target.Name, arguments.NumHosts)
	case "sandbox.pool.delete":
		return fmt.Sprintf("Delete sandbox pool %s/%s and cancel all active hosts", target.Namespace, target.Name)
	default:
		return fallback
	}
}

func presentSandboxResource(operation, namespace, name string, raw json.RawMessage, attrs map[string]any, fallback string) string {
	switch operation {
	case "sandbox.file.write":
		var arguments sandboxFileWriteArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		attrs["path"] = arguments.Path
		attrs["content_digest"] = digest(decodeSandboxContent(arguments.ContentBase64))
		return fmt.Sprintf("Write %s in sandbox %s/%s (content digest %s)", arguments.Path, namespace, name, attrs["content_digest"].(string)[:12])
	case "sandbox.file.delete":
		var arguments sandboxFileDeleteArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		attrs["path"], attrs["recursive"] = arguments.Path, fmt.Sprint(arguments.Recursive)
		return fmt.Sprintf("Delete %s from sandbox %s/%s (recursive: %t)", arguments.Path, namespace, name, arguments.Recursive)
	case "sandbox.file.mkdir":
		var arguments sandboxFileMkdirArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		attrs["path"] = arguments.Path
		return fmt.Sprintf("Create directory %s in sandbox %s/%s", arguments.Path, namespace, name)
	case "sandbox.process.kill":
		var arguments sandboxProcessKillArguments
		_ = decodeClosed(raw, &arguments, maxArgumentsBytes)
		attrs["pid"] = fmt.Sprint(arguments.PID)
		return fmt.Sprintf("Kill process %d in sandbox %s/%s", arguments.PID, namespace, name)
	case "sandbox.delete":
		return fmt.Sprintf("Delete sandbox %s/%s", namespace, name)
	default:
		return fallback
	}
}

var _ ClientBoundAdapter = (*sandboxAdapter)(nil)
var _ PlanCleaner = (*sandboxAdapter)(nil)
