// Package privilege implements the short-lived setup worker protocol.
package privilege

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	deploymentplan "github.com/osolmaz/unyolo/deployment/plan"
	deploymentruntime "github.com/osolmaz/unyolo/deployment/runtime"
	"github.com/osolmaz/unyolo/internal/host/bundle"
	hostdeployment "github.com/osolmaz/unyolo/internal/host/deployment"
)

const APIVersion = "unyolo.io/setup-worker/v1"

// Removal input kind values driven by the reviewed removal plan flow.
const (
	InputKindProfile      = "profile"
	InputKindInstallation = "installation"
	InputKindRemoval      = "removal"
)

var verifyIdentity = verifyWorkerIdentity

// Request starts one privileged planning session.
type Request struct {
	APIVersion   string `json:"api_version"`
	InputKind    string `json:"input_kind"`
	Profile      string `json:"profile,omitempty"`
	Installation string `json:"installation,omitempty"`
	RemoveState  bool   `json:"remove_state,omitempty"`
}

// Response returns the redacted canonical plan.
type Response struct {
	APIVersion  string                     `json:"api_version"`
	PlanDigest  string                     `json:"plan_digest,omitempty"`
	Plan        deploymentplan.Plan        `json:"plan,omitempty"`
	RemovalPlan hostdeployment.RemovalPlan `json:"removal_plan,omitempty"`
}

// Decision is the only message accepted after planning.
type Decision struct {
	APIVersion  string   `json:"api_version"`
	Action      string   `json:"action"`
	PlanDigest  string   `json:"plan_digest,omitempty"`
	SecretSlots []string `json:"secret_slots,omitempty"`
}

// SecretFrame is one transient credential-slot frame on the anonymous pipe.
type SecretFrame struct {
	APIVersion string `json:"api_version"`
	Name       string `json:"name"`
	Value      []byte `json:"value"`
}

// Result is the final closed worker outcome.
type Result struct {
	APIVersion    string                        `json:"api_version"`
	Status        string                        `json:"status"`
	Message       string                        `json:"message"`
	RemovalReport *hostdeployment.RemovalReport `json:"removal_report,omitempty"`
}

type deploymentEngine interface {
	Plan(context.Context, string) (hostdeployment.Planned, error)
	PlanInstallation(context.Context, string, string) (hostdeployment.Planned, error)
	ApplyDescriptors(context.Context, string, string, map[string]*os.File) (hostdeployment.Verification, error)
	ApplyInstallationDescriptors(context.Context, string, string, string, map[string]*os.File) (hostdeployment.Verification, error)
	PlanRemoval(context.Context, bool) (hostdeployment.RemovalPlan, error)
	ApplyRemoval(context.Context, hostdeployment.RemovalPlan) (hostdeployment.RemovalReport, error)
}

// Serve runs one plan-review-apply exchange and exits.
//
//nolint:cyclop // The privileged worker keeps identity, plan review, secret transfer, and apply in one framed session.
func Serve(ctx context.Context, input io.Reader, output io.Writer, engine deploymentEngine, reviewDeadline time.Duration) error {
	if err := verifyIdentity(); err != nil {
		return err
	}
	var request Request
	if err := deploymentruntime.ReadFrame(input, &request); err != nil {
		return err
	}
	if err := validateRequest(request); err != nil {
		return err
	}
	if request.InputKind == InputKindRemoval {
		return serveRemoval(ctx, input, output, engine, request, reviewDeadline)
	}
	var planned hostdeployment.Planned
	var err error
	if request.InputKind == InputKindInstallation {
		planned, err = engine.PlanInstallation(ctx, request.Installation, request.Profile)
	} else {
		planned, err = engine.Plan(ctx, request.Profile)
	}
	if err != nil {
		return err
	}
	if err := deploymentruntime.WriteFrame(output, Response{APIVersion: APIVersion, PlanDigest: planned.Plan.Digest, Plan: planned.Plan}); err != nil {
		return err
	}
	if reviewDeadline <= 0 {
		reviewDeadline = 5 * time.Minute
	}
	reviewContext, cancel := context.WithTimeout(ctx, reviewDeadline)
	defer cancel()
	decisionChannel := make(chan struct {
		value Decision
		err   error
	}, 1)
	go func() {
		var decision Decision
		err := deploymentruntime.ReadFrame(input, &decision)
		decisionChannel <- struct {
			value Decision
			err   error
		}{decision, err}
	}()
	var decision Decision
	select {
	case <-reviewContext.Done():
		return errors.New("setup worker review deadline expired")
	case decoded := <-decisionChannel:
		if decoded.err != nil {
			return decoded.err
		}
		decision = decoded.value
	}
	if decision.APIVersion != APIVersion {
		return errors.New("setup worker decision is invalid")
	}
	switch decision.Action {
	case "cancel":
		return deploymentruntime.WriteFrame(output, Result{APIVersion: APIVersion, Status: "cancelled", Message: "No host changes were applied"})
	case "apply":
		if decision.PlanDigest == "" || decision.PlanDigest != planned.Plan.Digest {
			return errors.New("setup worker decision does not match the reviewed plan")
		}
	default:
		return errors.New("setup worker accepts only apply or cancel")
	}
	required := RequiredSecretSlots(planned.Plan)
	slots := append([]string(nil), decision.SecretSlots...)
	slices.Sort(slots)
	if !slices.Equal(required, slots) {
		return errors.New("setup worker secret slots do not match the reviewed plan")
	}
	secretFiles, waitWriters, err := readSecretFrames(input, slots)
	if err != nil {
		return err
	}
	var report hostdeployment.Verification
	if request.InputKind == "installation" {
		report, err = engine.ApplyInstallationDescriptors(ctx, request.Installation, request.Profile, decision.PlanDigest, secretFiles)
	} else {
		report, err = engine.ApplyDescriptors(ctx, request.Profile, decision.PlanDigest, secretFiles)
	}
	closeFiles(secretFiles)
	writerErr := waitWriters()
	if err != nil || writerErr != nil {
		return errors.Join(err, writerErr)
	}
	return deploymentruntime.WriteFrame(output, Result{APIVersion: APIVersion, Status: "succeeded", Message: fmt.Sprintf("Verified deployment %s", report.DeploymentName)})
}

// validateRequest keeps every input-kind precondition in one closed trust boundary.
func validateRequest(request Request) error {
	if request.APIVersion != APIVersion {
		return errors.New("setup worker request API is invalid")
	}
	switch request.InputKind {
	case InputKindProfile:
		if request.Installation != "" || request.RemoveState ||
			!filepath.IsAbs(request.Profile) || filepath.Clean(request.Profile) != request.Profile {
			return errors.New("setup worker profile request is invalid")
		}
	case InputKindInstallation:
		if request.RemoveState ||
			!filepath.IsAbs(request.Profile) || filepath.Clean(request.Profile) != request.Profile ||
			!filepath.IsAbs(request.Installation) || filepath.Clean(request.Installation) != request.Installation {
			return errors.New("setup worker installation request is invalid")
		}
	case InputKindRemoval:
		if request.Profile != "" || request.Installation != "" {
			return errors.New("setup worker removal request is invalid")
		}
	default:
		return errors.New("setup worker request kind is invalid")
	}
	return nil
}

func serveRemoval(ctx context.Context, input io.Reader, output io.Writer, engine deploymentEngine, request Request, reviewDeadline time.Duration) error {
	plan, err := engine.PlanRemoval(ctx, request.RemoveState)
	if err != nil {
		return err
	}
	if err := deploymentruntime.WriteFrame(output, Response{APIVersion: APIVersion, RemovalPlan: plan}); err != nil {
		return err
	}
	if reviewDeadline <= 0 {
		reviewDeadline = 5 * time.Minute
	}
	reviewContext, cancel := context.WithTimeout(ctx, reviewDeadline)
	defer cancel()
	decisionChannel := make(chan struct {
		value Decision
		err   error
	}, 1)
	go func() {
		var decision Decision
		err := deploymentruntime.ReadFrame(input, &decision)
		decisionChannel <- struct {
			value Decision
			err   error
		}{decision, err}
	}()
	var decision Decision
	select {
	case <-reviewContext.Done():
		return errors.New("setup worker review deadline expired")
	case decoded := <-decisionChannel:
		if decoded.err != nil {
			return decoded.err
		}
		decision = decoded.value
	}
	if decision.APIVersion != APIVersion {
		return errors.New("setup worker decision is invalid")
	}
	switch decision.Action {
	case "cancel":
		return deploymentruntime.WriteFrame(output, Result{APIVersion: APIVersion, Status: "cancelled", Message: "No host changes were removed"})
	case "apply":
		if len(decision.SecretSlots) != 0 {
			return errors.New("setup worker removal decision must not carry secret slots")
		}
	default:
		return errors.New("setup worker accepts only apply or cancel")
	}
	report, err := engine.ApplyRemoval(ctx, plan)
	if err != nil {
		return err
	}
	return deploymentruntime.WriteFrame(output, Result{APIVersion: APIVersion, Status: "succeeded", Message: "Removed the recorded host installation", RemovalReport: &report})
}

// RequiredSecretSlots returns the ordered transient slots needed by a plan.
func RequiredSecretSlots(value deploymentplan.Plan) []string {
	var result []string
	for _, component := range value.Components {
		for _, credential := range component.Credentials {
			if credential.Action == "install" || credential.Action == "rotate" {
				result = append(result, credential.Slot)
			}
		}
	}
	slices.Sort(result)
	return result
}

//nolint:cyclop // Secret frames are validated, piped, and unwound as one bounded transfer.
func readSecretFrames(input io.Reader, slots []string) (map[string]*os.File, func() error, error) {
	files := map[string]*os.File{}
	type writeResult struct{ err error }
	results := make(chan writeResult, len(slots))
	for _, expected := range slots {
		var frame SecretFrame
		if err := deploymentruntime.ReadFrame(input, &frame); err != nil {
			closeFiles(files)
			return nil, nil, err
		}
		if frame.APIVersion != APIVersion || frame.Name != expected || len(frame.Value) == 0 || len(frame.Value) > 1024*1024 || strings.ContainsAny(frame.Name, "\x00\r\n=") {
			clear(frame.Value)
			closeFiles(files)
			return nil, nil, errors.New("setup worker secret frame is invalid")
		}
		reader, writer, err := os.Pipe()
		if err != nil {
			clear(frame.Value)
			closeFiles(files)
			return nil, nil, err
		}
		files[frame.Name] = reader
		value := frame.Value
		go func() {
			_, writeErr := writer.Write(value)
			closeErr := writer.Close()
			clear(value)
			results <- writeResult{errors.Join(writeErr, closeErr)}
		}()
	}
	wait := func() error {
		var result []error
		for range slots {
			if value := <-results; value.err != nil {
				result = append(result, value.err)
			}
		}
		return errors.Join(result...)
	}
	return files, wait, nil
}

func closeFiles(files map[string]*os.File) {
	for _, file := range files {
		_ = file.Close()
	}
}

//nolint:cyclop // Root-worker identity checks reject every unsafe invocation context explicitly.
func verifyWorkerIdentity() error {
	if os.Geteuid() != 0 {
		return errors.New("setup worker must run as root")
	}
	invoking := os.Getenv("SUDO_UID")
	uid, err := strconv.Atoi(invoking)
	if err != nil || uid <= 0 {
		return errors.New("setup worker requires a distinct sudo invoking user")
	}
	executable, err := os.Executable()
	if err != nil {
		return errors.New("resolve setup worker executable")
	}
	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil || !filepath.IsAbs(resolved) {
		return errors.New("resolve setup worker executable identity")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return errors.New("setup worker executable is not root-controlled")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("setup worker executable must be root-owned")
	}
	return nil
}

// NewProductionEngine creates the fixed worker host engine.
func NewProductionEngine() (*hostdeployment.Engine, error) {
	return hostdeployment.New(hostdeployment.Options{Paths: bundle.DefaultPaths()})
}
