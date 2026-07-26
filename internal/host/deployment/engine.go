// Package deployment orchestrates one canonical BrokerKit host deployment.
package deployment

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/deployment/api"
	deploymentplan "github.com/osolmaz/brokerkit/deployment/plan"
	"github.com/osolmaz/brokerkit/deployment/profile"
	adapterruntime "github.com/osolmaz/brokerkit/deployment/runtime"
	"github.com/osolmaz/brokerkit/deployment/transaction"
	"github.com/osolmaz/brokerkit/internal/host/bundle"
	"github.com/osolmaz/brokerkit/internal/host/identity"
	"github.com/osolmaz/brokerkit/internal/strictjson"
)

const exportAPIVersion = "brokerkit.io/host-export/v1"

// Options configures one host deployment engine.
type Options struct {
	Paths          bundle.Paths
	Manager        bundle.ServiceManager
	Development    bool
	AdapterTimeout time.Duration
	Identity       identity.Inspector
}

// Engine plans, applies, and verifies deployment packs.
type Engine struct{ options Options }

// Planned retains the immutable snapshot and component plans used by apply.
type Planned struct {
	Plan           deploymentplan.Plan
	Snapshot       profile.Snapshot
	Responses      []api.Response
	Accounts       map[string]identity.Account
	ActiveBundleID string
	Commands       map[string]adapterruntime.Command
}

// SecretSource binds one logical slot to a protected file for this invocation.
type SecretSource struct {
	Name   string
	Path   string
	Rotate bool
}

// Verification is a secret-safe full-host verification report.
type Verification struct {
	APIVersion       string                  `json:"api_version"`
	DeploymentName   string                  `json:"deployment_name"`
	DeploymentDigest string                  `json:"deployment_digest"`
	RuntimeBundleID  string                  `json:"runtime_bundle_id"`
	Healthy          bool                    `json:"healthy"`
	Components       []ComponentVerification `json:"components"`
}

// ComponentVerification is one adapter's safe verification evidence.
type ComponentVerification struct {
	ID       string   `json:"id"`
	Healthy  bool     `json:"healthy"`
	Evidence []string `json:"evidence,omitempty"`
	Problem  string   `json:"problem,omitempty"`
}

// Export is deterministic redacted observed state.
type Export struct {
	APIVersion       string                      `json:"api_version"`
	DeploymentName   string                      `json:"deployment_name"`
	DeploymentDigest string                      `json:"deployment_digest"`
	RuntimeBundleID  string                      `json:"runtime_bundle_id"`
	Accounts         map[string]identity.Account `json:"accounts"`
	Components       []ComponentVerification     `json:"components"`
}

// New creates an engine. Production callers must use fixed root-owned paths.
//
//nolint:cyclop // Construction rejects every production/development path overlap before retaining options.
func New(options Options) (*Engine, error) {
	if options.Paths.Root == "" || options.Paths.StateDir == "" {
		options.Paths = bundle.DefaultPaths()
	}
	if !filepath.IsAbs(options.Paths.Root) || !filepath.IsAbs(options.Paths.StateDir) {
		return nil, errors.New("host deployment paths must be absolute")
	}
	production := bundle.DefaultPaths()
	if options.Development {
		if options.Paths.Root == production.Root || options.Paths.StateDir == production.StateDir {
			return nil, errors.New("development host deployment requires isolated paths")
		}
	} else if options.Paths != production {
		return nil, errors.New("production host deployment uses fixed paths")
	}
	root, state := filepath.Clean(options.Paths.Root), filepath.Clean(options.Paths.StateDir)
	if root == state || strings.HasPrefix(root, state+string(filepath.Separator)) || strings.HasPrefix(state, root+string(filepath.Separator)) {
		return nil, errors.New("host deployment root and state paths must not overlap")
	}
	if options.Manager == nil {
		options.Manager = bundle.NewNativeManager()
	}
	return &Engine{options: options}, nil
}

// Validate verifies a pack and every signed component profile without host mutation.
func (engine *Engine) Validate(ctx context.Context, profileRoot string) (profile.Snapshot, error) {
	snapshot, err := profile.Load(profileRoot)
	if err != nil {
		return profile.Snapshot{}, err
	}
	for _, component := range deploymentComponents(snapshot) {
		response, runErr := engine.runComponent(ctx, snapshot, component.ID, api.ActionValidate, "", nil, false)
		if runErr != nil {
			return profile.Snapshot{}, runErr
		}
		if response.Status != "valid" {
			return profile.Snapshot{}, fmt.Errorf("component %q did not validate its profile", component.ID)
		}
	}
	return snapshot, nil
}

// Plan computes one canonical host plan and stages root-owned adapter copies.
//
//nolint:cyclop // Host planning binds profile, identity, runtime, component, and observed-state checks together.
func (engine *Engine) Plan(ctx context.Context, profileRoot string) (Planned, error) {
	if err := engine.requirePrivileged(); err != nil {
		return Planned{}, err
	}
	snapshot, err := profile.Load(profileRoot)
	if err != nil {
		return Planned{}, err
	}
	accounts, err := engine.options.Identity.InspectDeployment(ctx, snapshot.Deployment)
	if err != nil {
		return Planned{}, err
	}
	active, err := engine.activeBundle()
	if err != nil {
		return Planned{}, err
	}
	components := deploymentComponents(snapshot)
	responses := make([]api.Response, 0, len(components))
	commands := make(map[string]adapterruntime.Command, len(components))
	for _, component := range components {
		response, runErr := engine.runComponent(ctx, snapshot, component.ID, api.ActionPlan, "", nil, true)
		if runErr != nil {
			return Planned{}, runErr
		}
		responses = append(responses, response)
		command, commandErr := engine.adapterCommand(snapshot, component.ID, true)
		if commandErr != nil {
			return Planned{}, commandErr
		}
		commands[component.ID] = command
	}
	identityResponse, err := buildIdentityPlan(snapshot, accounts)
	if err != nil {
		return Planned{}, err
	}
	responses = append(responses, identityResponse)
	if err := validateCredentialOwnership(responses); err != nil {
		return Planned{}, err
	}
	observed, err := observedFingerprint(active, accounts, responses)
	if err != nil {
		return Planned{}, err
	}
	value, err := deploymentplan.Build(snapshot, observed, responses, active)
	if err != nil {
		return Planned{}, err
	}
	return Planned{Plan: value, Snapshot: snapshot, Responses: responses, Accounts: accounts, ActiveBundleID: active, Commands: commands}, nil
}

// Apply replans, binds the exact digest, and executes one durable transaction.
func (engine *Engine) Apply(ctx context.Context, profileRoot, expectedPlan string, sources []SecretSource) (Verification, error) {
	secretFiles, err := openSecretSources(sources)
	if err != nil {
		return Verification{}, err
	}
	defer closeSecretSources(secretFiles)
	return engine.ApplyDescriptors(ctx, profileRoot, expectedPlan, secretFiles)
}

// ApplyDescriptors applies with already-open one-use read-only secret descriptors.
//
//nolint:cyclop // Apply rechecks every plan binding before entering the transaction.
func (engine *Engine) ApplyDescriptors(ctx context.Context, profileRoot, expectedPlan string, secretFiles map[string]*os.File) (Verification, error) {
	lock, err := acquireHostLock(engine.options.Paths.StateDir)
	if err != nil {
		return Verification{}, err
	}
	defer func() { _ = lock.close() }()
	planned, err := engine.Plan(ctx, profileRoot)
	if err != nil {
		return Verification{}, err
	}
	coordinator := transaction.Coordinator{StateDirectory: engine.options.Paths.StateDir}
	if err := coordinator.Recover(ctx, engine.recoveryHandlers(planned)); err != nil {
		return Verification{}, err
	}
	planned, err = engine.Plan(ctx, profileRoot)
	if err != nil {
		return Verification{}, err
	}
	if expectedPlan == "" || planned.Plan.Digest != expectedPlan {
		return Verification{}, errors.New("plan_stale: current host plan does not match --expect-plan")
	}
	if planned.Plan.Kind == deploymentplan.KindBlocked {
		return Verification{}, errors.New("host deployment plan is blocked")
	}
	if planned.Plan.Kind == deploymentplan.KindNoop {
		return engine.verifyPlanned(ctx, planned)
	}
	steps, err := engine.steps(planned, secretFiles)
	if err != nil {
		return Verification{}, err
	}
	if err := coordinator.Run(ctx, planned.Snapshot.Digest, planned.Plan.Digest, planned.Snapshot.Manifest.BundleID, planned.ActiveBundleID, steps); err != nil {
		return Verification{}, err
	}
	return engine.Verify(ctx, profileRoot)
}

// Verify checks the active runtime and every real component adapter path.
func (engine *Engine) Verify(ctx context.Context, profileRoot string) (Verification, error) {
	planned, err := engine.Plan(ctx, profileRoot)
	if err != nil {
		return Verification{}, err
	}
	return engine.verifyPlanned(ctx, planned)
}

func (engine *Engine) verifyPlanned(ctx context.Context, planned Planned) (Verification, error) {
	report := Verification{
		APIVersion: "brokerkit.io/host-verification/v1", DeploymentName: planned.Snapshot.Deployment.Name,
		DeploymentDigest: planned.Snapshot.Digest, RuntimeBundleID: planned.Snapshot.Manifest.BundleID, Healthy: true,
	}
	if planned.ActiveBundleID != planned.Snapshot.Manifest.BundleID {
		report.Healthy = false
		return report, errors.New("configured runtime bundle is not active")
	}
	installer := engine.installer()
	status, err := installer.Status(ctx)
	if err != nil || !status.Healthy {
		report.Healthy = false
		if err != nil {
			return report, err
		}
		return report, errors.New("active runtime bundle is unhealthy")
	}
	for _, component := range deploymentComponents(planned.Snapshot) {
		response, runErr := engine.runComponent(ctx, planned.Snapshot, component.ID, api.ActionVerify, "", nil, true)
		entry := ComponentVerification{ID: component.ID, Healthy: runErr == nil && response.Status == "verified", Evidence: response.Verification}
		if runErr != nil {
			entry.Problem = runErr.Error()
			report.Healthy = false
		} else if response.Status != "verified" {
			entry.Problem = "component verification did not succeed"
			report.Healthy = false
		}
		report.Components = append(report.Components, entry)
	}
	if !report.Healthy {
		return report, errors.New("BrokerKit host requires repair")
	}
	return report, nil
}

// ExportObserved returns a deterministic redacted status projection.
func (engine *Engine) ExportObserved(ctx context.Context, profileRoot string) (Export, error) {
	planned, err := engine.Plan(ctx, profileRoot)
	if err != nil {
		return Export{}, err
	}
	verification, verifyErr := engine.verifyPlanned(ctx, planned)
	result := Export{
		APIVersion: exportAPIVersion, DeploymentName: planned.Snapshot.Deployment.Name,
		DeploymentDigest: planned.Snapshot.Digest, RuntimeBundleID: planned.ActiveBundleID,
		Accounts: planned.Accounts, Components: verification.Components,
	}
	return result, verifyErr
}

func (engine *Engine) requirePrivileged() error {
	if !engine.options.Development && os.Geteuid() != 0 {
		return errors.New("production host deployment requires root")
	}
	return nil
}

func (engine *Engine) installer() bundle.Installer {
	return bundle.Installer{Paths: engine.options.Paths, Manager: engine.options.Manager, Development: engine.options.Development}
}

func (engine *Engine) activeBundle() (string, error) {
	data, err := os.ReadFile(filepath.Join(engine.options.Paths.StateDir, "activation.json")) // #nosec G304 -- fixed host state path.
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var activation bundle.Activation
	if err := strictjson.Decode(data, &activation, true); err != nil || activation.APIVersion != bundle.APIVersion || activation.RecoveryRequired {
		return "", errors.New("host activation record is invalid or requires recovery")
	}
	return activation.ActiveBundleID, nil
}

func buildIdentityPlan(snapshot profile.Snapshot, accounts map[string]identity.Account) (api.Response, error) {
	response := api.Response{APIVersion: api.APIVersion, ComponentID: "host-identity", Status: "planned"}
	for _, agent := range snapshot.Deployment.Agents {
		account := accounts["agent:"+agent.ID]
		if !account.Missing {
			continue
		}
		response.Actions = append(response.Actions, api.PlannedAction{
			ID: "account-" + agent.ID, Type: "create", Risk: "high",
			Resource:      api.Resource{Kind: "account", ID: agent.UnixUser},
			DesiredDigest: digestText(agent.UnixUser + "\x00" + agent.Home + "\x00" + agent.Shell),
		})
	}
	data, err := json.Marshal(response.Actions)
	if err != nil {
		return api.Response{}, err
	}
	response.PlanDigest = digestText(string(data))
	return response, response.Validate()
}

func digestText(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("sha256:%x", sum)
}

func validateCredentialOwnership(responses []api.Response) error {
	owners := map[string]string{}
	for _, response := range responses {
		for _, credential := range response.Credentials {
			if owner := owners[credential.Slot]; owner != "" && owner != response.ComponentID {
				return fmt.Errorf("credential slot %q is claimed by components %q and %q", credential.Slot, owner, response.ComponentID)
			}
			owners[credential.Slot] = response.ComponentID
		}
	}
	return nil
}

func observedFingerprint(active string, accounts map[string]identity.Account, responses []api.Response) (string, error) {
	componentDigests := map[string]string{}
	for _, response := range responses {
		componentDigests[response.ComponentID] = response.PlanDigest
	}
	data, err := json.Marshal(struct {
		Active     string                      `json:"active_bundle_id"`
		Accounts   map[string]identity.Account `json:"accounts"`
		Components map[string]string           `json:"component_plan_digests"`
	}{active, accounts, componentDigests})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum), nil
}

func deploymentComponents(snapshot profile.Snapshot) []profile.Component {
	result := append([]profile.Component(nil), snapshot.Deployment.Components...)
	for _, integration := range snapshot.Deployment.Integrations {
		result = append(result, profile.Component{ID: integration.Kind, Profile: integration.Profile})
	}
	return result
}

func componentByID(snapshot profile.Snapshot, id string) (profile.Component, bundle.Component, error) {
	var desired profile.Component
	found := false
	for _, component := range deploymentComponents(snapshot) {
		if component.ID == id {
			desired, found = component, true
			break
		}
	}
	if !found {
		return profile.Component{}, bundle.Component{}, fmt.Errorf("unknown deployment component %q", id)
	}
	for _, component := range snapshot.Manifest.Components {
		if component.Name == id {
			return desired, component, nil
		}
	}
	return profile.Component{}, bundle.Component{}, fmt.Errorf("component %q is absent from runtime manifest", id)
}

func (engine *Engine) runComponent(ctx context.Context, snapshot profile.Snapshot, id string, action api.Action, planDigest string, secrets []adapterruntime.Secret, staged bool) (api.Response, error) {
	desired, runtimeComponent, err := componentByID(snapshot, id)
	if err != nil {
		return api.Response{}, err
	}
	command, err := engine.adapterCommand(snapshot, id, staged)
	if err != nil {
		return api.Response{}, err
	}
	files := make([]api.File, 0, len(snapshot.Files))
	paths := make([]string, 0, len(snapshot.Files))
	for path := range snapshot.Files {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	for _, path := range paths {
		file := snapshot.Files[path]
		files = append(files, api.File{Path: file.Path, SHA256: file.SHA256, Data: file.Data})
	}
	request := api.Request{
		APIVersion: api.APIVersion, Action: action, DeploymentDigest: snapshot.Digest,
		PlanDigest: planDigest, ComponentID: id, Profile: snapshot.Files[desired.Profile.Path].Data,
		Files: files, Agents: agentBindings(snapshot, id),
	}
	response, err := (adapterruntime.Runner{Timeout: engine.options.AdapterTimeout}).Run(ctx, command, request, secrets)
	if err != nil {
		return api.Response{}, fmt.Errorf("component %q: %w", id, err)
	}
	if err := adapterruntime.ValidateOwnership(response, runtimeComponent); err != nil {
		return api.Response{}, fmt.Errorf("component %q: %w", id, err)
	}
	return response, nil
}

func agentBindings(snapshot profile.Snapshot, componentID string) []api.AgentBinding {
	var result []api.AgentBinding
	for _, agent := range snapshot.Deployment.Agents {
		bound := slices.Contains(agent.ComponentIDs, componentID)
		for _, integration := range snapshot.Deployment.Integrations {
			bound = bound || (integration.Kind == componentID && integration.AgentID == agent.ID)
		}
		if bound {
			result = append(result, api.AgentBinding{ID: agent.ID, ClientID: agent.ClientID, UnixUser: agent.UnixUser, Home: agent.Home})
		}
	}
	slices.SortFunc(result, func(a, b api.AgentBinding) int { return strings.Compare(a.ID, b.ID) })
	return result
}

func (engine *Engine) adapterCommand(snapshot profile.Snapshot, id string, staged bool) (adapterruntime.Command, error) {
	_, component, err := componentByID(snapshot, id)
	if err != nil {
		return adapterruntime.Command{}, err
	}
	if component.Setup == nil {
		return adapterruntime.Command{}, errors.New("component has no setup adapter")
	}
	path, err := snapshot.VerifyArtifact(component.Source, component.SHA256)
	if err != nil {
		return adapterruntime.Command{}, err
	}
	if staged {
		path, err = engine.stageAdapter(snapshot, component, path)
		if err != nil {
			return adapterruntime.Command{}, err
		}
	}
	return adapterruntime.Command{Executable: path, Arguments: append([]string(nil), component.Setup.Arguments...)}, nil
}

func (engine *Engine) steps(planned Planned, secretFiles map[string]*os.File) ([]transaction.Step, error) {
	responseByID := map[string]api.Response{}
	for _, response := range planned.Responses {
		responseByID[response.ComponentID] = response
	}
	steps, err := engine.identitySteps(planned)
	if err != nil {
		return nil, err
	}
	for _, component := range deploymentComponents(planned.Snapshot) {
		component := component
		response := responseByID[component.ID]
		secrets, err := secretsForComponent(response, secretFiles)
		if err != nil {
			return nil, err
		}
		steps = append(steps, transaction.Step{
			ID: "component." + component.ID, Kind: "component:" + component.ID,
			Apply: func(ctx context.Context) (string, error) {
				applied, applyErr := engine.runComponent(ctx, planned.Snapshot, component.ID, api.ActionApply, response.PlanDigest, secrets, true)
				if applyErr != nil {
					return "", applyErr
				}
				if applied.Status != "applied" {
					return "", errors.New("component apply did not succeed")
				}
				return applied.RollbackHandle, nil
			},
			Rollback: func(ctx context.Context, handle string) error {
				return engine.rollbackComponent(ctx, planned.Snapshot, component.ID, response.PlanDigest, handle)
			},
		})
	}
	if planned.ActiveBundleID != planned.Snapshot.Manifest.BundleID {
		steps = append(steps, transaction.Step{
			ID: "runtime.activate", Kind: "runtime",
			Apply: func(ctx context.Context) (string, error) {
				manifestFile := planned.Snapshot.Files[planned.Snapshot.Deployment.Runtime.Manifest.Path]
				return "", engine.installer().Activate(ctx, planned.Snapshot.Manifest, manifestFile.Data, planned.Snapshot.Root)
			},
			Rollback: func(ctx context.Context, _ string) error { return engine.installer().Rollback(ctx) },
		})
	} else {
		for _, service := range restartServices(planned) {
			service := service
			steps = append(steps, transaction.Step{
				ID: "service." + service, Kind: "service:" + service,
				Apply: func(ctx context.Context) (string, error) {
					if err := engine.options.Manager.Stop(ctx, service); err != nil {
						return "", err
					}
					return "", engine.options.Manager.Start(ctx, service)
				},
				Rollback: func(ctx context.Context, _ string) error { return engine.options.Manager.Start(ctx, service) },
			})
		}
	}
	steps = append(steps, transaction.Step{
		ID: "host.verify", Kind: "verification",
		Apply: func(ctx context.Context) (string, error) {
			_, verifyErr := engine.Verify(ctx, planned.Snapshot.Root)
			return "", verifyErr
		},
		Rollback: func(context.Context, string) error { return nil },
	})
	return steps, nil
}

func (engine *Engine) identitySteps(planned Planned) ([]transaction.Step, error) {
	var steps []transaction.Step
	for _, agent := range planned.Snapshot.Deployment.Agents {
		if !planned.Accounts["agent:"+agent.ID].Missing {
			continue
		}
		if runtime.GOOS != "linux" {
			return nil, errors.New("managed agent creation is supported only on Linux")
		}
		agent := agent
		command, err := identity.SafeManagedCommand(agent)
		if err != nil {
			return nil, err
		}
		steps = append(steps, transaction.Step{
			ID: "identity." + agent.ID, Kind: "identity:" + agent.ID,
			Apply: func(ctx context.Context) (string, error) {
				process := exec.CommandContext(ctx, command[0], command[1:]...) // #nosec G204 -- fixed account command with validated profile fields.
				if err := process.Run(); err != nil {
					return "", fmt.Errorf("create managed agent %q: %w", agent.ID, err)
				}
				return "retained", nil
			},
			Rollback: func(context.Context, string) error { return nil },
		})
	}
	return steps, nil
}

func (engine *Engine) recoveryHandlers(planned Planned) map[string]func(context.Context, string) error {
	handlers := map[string]func(context.Context, string) error{
		"runtime":      func(ctx context.Context, _ string) error { return engine.installer().Rollback(ctx) },
		"verification": func(context.Context, string) error { return nil },
	}
	responseByID := map[string]api.Response{}
	for _, response := range planned.Responses {
		responseByID[response.ComponentID] = response
	}
	for _, component := range deploymentComponents(planned.Snapshot) {
		component := component
		response := responseByID[component.ID]
		handlers["component:"+component.ID] = func(ctx context.Context, handle string) error {
			return engine.rollbackComponent(ctx, planned.Snapshot, component.ID, response.PlanDigest, handle)
		}
	}
	for _, agent := range planned.Snapshot.Deployment.Agents {
		handlers["identity:"+agent.ID] = func(context.Context, string) error { return nil }
	}
	for _, service := range restartServices(planned) {
		service := service
		handlers["service:"+service] = func(ctx context.Context, _ string) error { return engine.options.Manager.Start(ctx, service) }
	}
	return handlers
}

func restartServices(planned Planned) []string {
	wanted := map[string]bool{}
	for _, response := range planned.Responses {
		restart := false
		for _, action := range response.Actions {
			restart = restart || action.Restart
		}
		if !restart {
			continue
		}
		_, component, err := componentByID(planned.Snapshot, response.ComponentID)
		if err != nil {
			continue
		}
		for _, service := range component.Services {
			wanted[service] = true
		}
	}
	result := make([]string, 0, len(wanted))
	for service := range wanted {
		result = append(result, service)
	}
	slices.Sort(result)
	return result
}

func (engine *Engine) rollbackComponent(ctx context.Context, snapshot profile.Snapshot, id, planDigest, handle string) error {
	desired, _, err := componentByID(snapshot, id)
	if err != nil {
		return err
	}
	command, err := engine.adapterCommand(snapshot, id, true)
	if err != nil {
		return err
	}
	request := api.Request{
		APIVersion: api.APIVersion, Action: api.ActionRollback, DeploymentDigest: snapshot.Digest,
		PlanDigest: planDigest, ComponentID: id, Profile: snapshot.Files[desired.Profile.Path].Data,
		RollbackHandle: handle,
	}
	response, err := (adapterruntime.Runner{Timeout: engine.options.AdapterTimeout}).Run(ctx, command, request, nil)
	if err != nil {
		return err
	}
	if response.Status != "rolled_back" {
		return errors.New("component rollback did not succeed")
	}
	return nil
}

func secretsForComponent(response api.Response, files map[string]*os.File) ([]adapterruntime.Secret, error) {
	var result []adapterruntime.Secret
	for _, credential := range response.Credentials {
		if credential.Action == "retain" || credential.Action == "remove" {
			continue
		}
		file := files[credential.Slot]
		if file == nil {
			return nil, fmt.Errorf("credential slot %q requires --secret-file", credential.Slot)
		}
		result = append(result, adapterruntime.Secret{Name: credential.Slot, File: file, Rotate: credential.Action == "rotate"})
	}
	return result, nil
}

//nolint:cyclop // One-use secret sources are opened, permission-checked, and unwound as one operation.
func openSecretSources(sources []SecretSource) (map[string]*os.File, error) {
	result := map[string]*os.File{}
	for _, source := range sources {
		if source.Name == "" || result[source.Name] != nil || !filepath.IsAbs(source.Path) || filepath.Clean(source.Path) != source.Path {
			closeSecretSources(result)
			return nil, errors.New("secret source is invalid or duplicated")
		}
		info, err := os.Lstat(source.Path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			closeSecretSources(result)
			return nil, fmt.Errorf("secret source %q must be a real owner-only regular file", source.Name)
		}
		file, err := os.Open(source.Path) // #nosec G304 -- operator path is validated before opening.
		if err != nil {
			closeSecretSources(result)
			return nil, errors.New("open secret source")
		}
		result[source.Name] = file
	}
	return result, nil
}

func closeSecretSources(files map[string]*os.File) {
	for _, file := range files {
		_ = file.Close()
	}
}
