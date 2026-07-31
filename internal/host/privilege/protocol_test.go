package privilege

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/deployment/api"
	deploymentplan "github.com/osolmaz/unyolo/deployment/plan"
	deploymentruntime "github.com/osolmaz/unyolo/deployment/runtime"
	hostdeployment "github.com/osolmaz/unyolo/internal/host/deployment"
)

type fakeDeploymentEngine struct {
	planned       hostdeployment.Planned
	report        hostdeployment.Verification
	secret        string
	removalPlan   hostdeployment.RemovalPlan
	removalReport hostdeployment.RemovalReport
	removalErr    error
}

func (engine *fakeDeploymentEngine) Plan(context.Context, string) (hostdeployment.Planned, error) {
	return engine.planned, nil
}

func (engine *fakeDeploymentEngine) PlanInstallation(context.Context, string, string) (hostdeployment.Planned, error) {
	return engine.planned, nil
}

func (engine *fakeDeploymentEngine) ApplyDescriptors(_ context.Context, _ string, _ string, files map[string]*os.File) (hostdeployment.Verification, error) {
	if file := files["token"]; file != nil {
		data, err := io.ReadAll(file)
		if err != nil {
			return hostdeployment.Verification{}, err
		}
		engine.secret = string(data)
	}
	return engine.report, nil
}

func (engine *fakeDeploymentEngine) ApplyInstallationDescriptors(ctx context.Context, _ string, profile, digest string, files map[string]*os.File) (hostdeployment.Verification, error) {
	return engine.ApplyDescriptors(ctx, profile, digest, files)
}

func (engine *fakeDeploymentEngine) PlanRemoval(context.Context, bool) (hostdeployment.RemovalPlan, error) {
	return engine.removalPlan, engine.removalErr
}

func (engine *fakeDeploymentEngine) ApplyRemoval(context.Context, hostdeployment.RemovalPlan) (hostdeployment.RemovalReport, error) {
	return engine.removalReport, engine.removalErr
}

func TestWorkerServeCancelAndApply(t *testing.T) {
	original := verifyIdentity
	verifyIdentity = func() error { return nil }
	t.Cleanup(func() { verifyIdentity = original })
	digest := "sha256:" + strings.Repeat("a", 64)
	engine := &fakeDeploymentEngine{
		planned: hostdeployment.Planned{Plan: deploymentplan.Plan{Digest: digest, Components: []deploymentplan.Component{{ID: "github", Credentials: []api.CredentialAction{{Slot: "token", Action: "install"}}}}}},
		report:  hostdeployment.Verification{DeploymentName: "host", Healthy: true},
	}
	for _, test := range []struct {
		name     string
		decision Decision
		secret   *SecretFrame
		status   string
	}{
		{"cancel", Decision{APIVersion: APIVersion, Action: "cancel"}, nil, "cancelled"},
		{"apply", Decision{APIVersion: APIVersion, Action: "apply", PlanDigest: digest, SecretSlots: []string{"token"}}, &SecretFrame{APIVersion: APIVersion, Name: "token", Value: []byte("transient-secret")}, "succeeded"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var input, output bytes.Buffer
			for _, value := range []any{Request{APIVersion: APIVersion, InputKind: "profile", Profile: "/tmp/profile"}, test.decision} {
				if err := deploymentruntime.WriteFrame(&input, value); err != nil {
					t.Fatal(err)
				}
			}
			if test.secret != nil {
				if err := deploymentruntime.WriteFrame(&input, *test.secret); err != nil {
					t.Fatal(err)
				}
			}
			if err := Serve(t.Context(), &input, &output, engine, time.Second); err != nil {
				t.Fatal(err)
			}
			var response Response
			if err := deploymentruntime.ReadFrame(&output, &response); err != nil || response.PlanDigest != digest {
				t.Fatalf("response = %#v, %v", response, err)
			}
			var result Result
			if err := deploymentruntime.ReadFrame(&output, &result); err != nil || result.Status != test.status {
				t.Fatalf("result = %#v, %v", result, err)
			}
		})
	}
	if engine.secret != "transient-secret" {
		t.Fatalf("secret = %q", engine.secret)
	}
}

func TestWorkerServeRejectsInvalidDecisions(t *testing.T) {
	original := verifyIdentity
	verifyIdentity = func() error { return nil }
	t.Cleanup(func() { verifyIdentity = original })
	digest := "sha256:" + strings.Repeat("a", 64)
	engine := &fakeDeploymentEngine{planned: hostdeployment.Planned{Plan: deploymentplan.Plan{Digest: digest}}}
	for _, decision := range []Decision{
		{APIVersion: "old", Action: "cancel"},
		{APIVersion: APIVersion, Action: "unknown"},
		{APIVersion: APIVersion, Action: "apply", PlanDigest: "wrong"},
		{APIVersion: APIVersion, Action: "apply", PlanDigest: digest, SecretSlots: []string{"extra"}},
	} {
		var input, output bytes.Buffer
		_ = deploymentruntime.WriteFrame(&input, Request{APIVersion: APIVersion, InputKind: "profile", Profile: "/tmp/profile"})
		_ = deploymentruntime.WriteFrame(&input, decision)
		if err := Serve(t.Context(), &input, &output, engine, time.Second); err == nil {
			t.Fatalf("decision was accepted: %#v", decision)
		}
	}
	verifyIdentity = func() error { return errors.New("identity") }
	if err := Serve(t.Context(), &bytes.Buffer{}, &bytes.Buffer{}, engine, time.Second); err == nil {
		t.Fatal("worker identity failure was ignored")
	}
}

func TestReadSecretFramesUsesAnonymousDescriptors(t *testing.T) {
	var input bytes.Buffer
	for _, frame := range []SecretFrame{
		{APIVersion: APIVersion, Name: "a", Value: []byte("first-secret")},
		{APIVersion: APIVersion, Name: "b", Value: []byte("second-secret")},
	} {
		if err := deploymentruntime.WriteFrame(&input, frame); err != nil {
			t.Fatal(err)
		}
	}
	files, wait, err := readSecretFrames(&input, []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"a": "first-secret", "b": "second-secret"} {
		data, readErr := io.ReadAll(files[name])
		if readErr != nil || string(data) != want {
			t.Fatalf("slot %s = %q, %v", name, data, readErr)
		}
	}
	closeFiles(files)
	if err := wait(); err != nil {
		t.Fatal(err)
	}
}

func testWorkerPlan() deploymentplan.Plan {
	return deploymentplan.Plan{Components: []deploymentplan.Component{
		{ID: "one", Credentials: []api.CredentialAction{{Slot: "zeta", Action: "install"}}},
		{ID: "two", Credentials: []api.CredentialAction{{Slot: "ignored", Action: "retain"}, {Slot: "alpha", Action: "rotate"}}},
	}}
}

func TestReadSecretFramesRejectsInvalidInput(t *testing.T) {
	for _, frame := range []SecretFrame{
		{APIVersion: "old", Name: "slot", Value: []byte("secret")},
		{APIVersion: APIVersion, Name: "wrong", Value: []byte("secret")},
		{APIVersion: APIVersion, Name: "slot"},
	} {
		var input bytes.Buffer
		if err := deploymentruntime.WriteFrame(&input, frame); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readSecretFrames(&input, []string{"slot"}); err == nil {
			t.Fatalf("secret frame was accepted: %#v", frame)
		}
	}
	if _, _, err := readSecretFrames(bytes.NewReader([]byte("bad")), []string{"slot"}); err == nil {
		t.Fatal("malformed frame was accepted")
	}
}

func TestWorkerIdentityRejectsUnprivilegedProcess(t *testing.T) {
	if err := verifyWorkerIdentity(); err == nil {
		t.Skip("test process is privileged")
	}
}

func TestRequiredSecretSlotsIsStable(t *testing.T) {
	value := testWorkerPlan()
	got := RequiredSecretSlots(value)
	if len(got) != 2 || got[0] != "alpha" || got[1] != "zeta" {
		t.Fatalf("RequiredSecretSlots() = %v", got)
	}
}
