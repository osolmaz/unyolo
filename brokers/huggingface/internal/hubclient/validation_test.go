package hubclient

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestTypedClientsRejectInvalidInputsBeforeTransport(t *testing.T) {
	client, err := New("https://huggingface.co", "secret", WithMaxResponseBytes(1024), WithTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	badRepo := RepoRef{Type: RepoTypeModel, Owner: "../acme", Name: "demo"}
	badBucket := BucketRef{Namespace: "acme", Name: "../data"}
	badSpace := SpaceRef{Owner: "acme", Name: "../demo"}
	badSandbox := SandboxRef{Namespace: "acme", JobID: "bad/id"}
	badPool := SandboxPoolRef{Namespace: "acme", Name: "bad/pool"}

	calls := map[string]func() error{
		"repo create": func() error {
			_, err := client.CreateRepo(ctx, CreateRepoInput{Ref: badRepo, Visibility: VisibilityPublic})
			return err
		},
		"repo delete":      func() error { return client.DeleteRepo(ctx, badRepo) },
		"repo move source": func() error { return client.MoveRepo(ctx, badRepo, "acme", "demo") },
		"repo move destination": func() error {
			return client.MoveRepo(ctx, RepoRef{Type: RepoTypeModel, Owner: "acme", Name: "demo"}, "../bad", "demo")
		},
		"repo visibility": func() error { _, err := client.UpdateRepoVisibility(ctx, badRepo, VisibilityPrivate); return err },
		"repo visibility mode": func() error {
			_, err := client.UpdateRepoVisibility(ctx, RepoRef{Type: RepoTypeModel, Owner: "acme", Name: "demo"}, VisibilityProtected)
			return err
		},
		"repo gating": func() error {
			return client.UpdateRepoGating(ctx, RepoRef{Type: RepoTypeModel, Owner: "acme", Name: "demo"}, "invalid")
		},
		"refs list": func() error { _, err := client.ListRefs(ctx, badRepo); return err },
		"branch create": func() error {
			return client.CreateBranch(ctx, RepoRef{Type: RepoTypeModel, Owner: "acme", Name: "demo"}, "bad..name", "main")
		},
		"branch delete": func() error {
			return client.DeleteBranch(ctx, RepoRef{Type: RepoTypeModel, Owner: "acme", Name: "demo"}, "bad name")
		},
		"tag create": func() error {
			return client.CreateTag(ctx, RepoRef{Type: RepoTypeModel, Owner: "acme", Name: "demo"}, "v1", "", "bad ref")
		},
		"tag delete": func() error {
			return client.DeleteTag(ctx, RepoRef{Type: RepoTypeModel, Owner: "acme", Name: "demo"}, "bad~tag")
		},
		"bucket info": func() error { _, err := client.BucketInfo(ctx, badBucket); return err },
		"bucket batch": func() error {
			return client.ApplyBucketBatch(ctx, badBucket, []BucketBatchOperation{{Type: "deleteFile", Path: "file"}})
		},
		"bucket move":   func() error { return client.MoveBucket(ctx, BucketRef{Namespace: "acme", Name: "data"}, badBucket) },
		"space runtime": func() error { _, err := client.SpaceRuntime(ctx, badSpace); return err },
		"space restart": func() error { _, err := client.RestartSpace(ctx, badSpace, false); return err },
		"space pause":   func() error { _, err := client.PauseSpace(ctx, badSpace); return err },
		"space hardware": func() error {
			_, err := client.RequestSpaceHardware(ctx, SpaceRef{Owner: "acme", Name: "demo"}, "root-shell", nil)
			return err
		},
		"space sleep": func() error {
			_, err := client.SetSpaceSleepTime(ctx, SpaceRef{Owner: "acme", Name: "demo"}, -2)
			return err
		},
		"space variable key": func() error {
			return client.SetSpaceVariable(ctx, SpaceRef{Owner: "acme", Name: "demo"}, "BAD-KEY", "value", "")
		},
		"space variable value": func() error {
			return client.SetSpaceVariable(ctx, SpaceRef{Owner: "acme", Name: "demo"}, "KEY", strings.Repeat("x", maxVariableValueBytes+1), "")
		},
		"space variable delete": func() error { return client.DeleteSpaceVariable(ctx, SpaceRef{Owner: "acme", Name: "demo"}, "BAD-KEY") },
		"sandbox state":         func() error { _, err := client.SandboxState(ctx, badSandbox); return err },
		"sandbox cancel": func() error {
			return client.CancelSandboxJob(ctx, SandboxRef{Namespace: "acme", JobID: "job", LocalID: "local"})
		},
		"sandbox create": func() error {
			_, err := client.CreateSandbox(ctx, SandboxCreateSpec{Namespace: "acme", Name: "review", OperationID: "bad/id"})
			return err
		},
		"sandbox pool create": func() error {
			_, err := client.CreateSandboxPoolHost(ctx, SandboxPoolSpec{Ref: badPool, OperationID: "operation", Image: "python:3.12", Flavor: "cpu-basic", SandboxesPerHost: 10})
			return err
		},
		"sandbox pool list":      func() error { _, err := client.ListSandboxPool(ctx, badPool); return err },
		"sandbox operation list": func() error { _, err := client.ListSandboxesByOperation(ctx, "../acme", "operation"); return err },
		"sandbox command": func() error {
			_, err := client.RunSandboxCommand(ctx, badSandbox, SandboxCommand{Argv: []string{"id"}, MaxOutputBytes: 1024})
			return err
		},
		"sandbox file stat":   func() error { _, err := client.SandboxFileStat(ctx, badSandbox, ""); return err },
		"sandbox file write":  func() error { return client.WriteSandboxFile(ctx, badSandbox, "/tmp/file", "9999", []byte("x")) },
		"sandbox mkdir":       func() error { return client.MakeSandboxDirectory(ctx, badSandbox, "") },
		"sandbox file delete": func() error { return client.DeleteSandboxFile(ctx, badSandbox, "", false) },
		"sandbox kill":        func() error { return client.KillSandboxProcess(ctx, badSandbox, 0) },
		"sandbox pooled create": func() error {
			_, err := client.CreateSandboxInPool(ctx, SandboxRef{Namespace: "acme", JobID: "job", LocalID: "local"}, nil, nil)
			return err
		},
	}
	for name, call := range calls {
		if err := call(); err == nil {
			t.Errorf("%s accepted invalid input", name)
		}
	}
}

func TestClientErrorClassificationAndResponseBounds(t *testing.T) {
	for _, test := range []struct {
		status int
		code   ErrorCode
	}{
		{http.StatusUnauthorized, CodeUnauthorized}, {http.StatusForbidden, CodeForbidden},
		{http.StatusNotFound, CodeNotFound}, {http.StatusConflict, CodeConflict},
		{http.StatusBadRequest, CodeInvalid}, {http.StatusInternalServerError, CodeUnavailable},
		{http.StatusOK, CodeResponseInvalid},
	} {
		if got := statusError(test.status, http.Header{}); got.Code != test.code {
			t.Errorf("statusError(%d) = %s, want %s", test.status, got.Code, test.code)
		}
	}
	for _, code := range []ErrorCode{CodeInvalid, CodeUnauthorized, CodeForbidden, CodeNotFound, CodeConflict, CodeRateLimited, CodeResponseInvalid} {
		if !(&Error{Code: code}).Definitive() {
			t.Errorf("%s should be definitive", code)
		}
	}
	if (&Error{Code: CodeResultUnknown}).Definitive() {
		t.Fatal("unknown result classified as definitive")
	}
	var output map[string]any
	if err := decodeResponse([]byte(`{"ok":true}`), &output, 4, http.StatusOK); err == nil {
		t.Fatal("oversized response accepted")
	}
	if err := decodeResponse([]byte(`not-json`), &output, 1024, http.StatusOK); err == nil {
		t.Fatal("invalid JSON response accepted")
	}
	if err := decodeResponse(nil, nil, 1, http.StatusNoContent); err != nil {
		t.Fatal(err)
	}
	if _, err := renderBoundPath("/api/{id}", nil, json.RawMessage(`{"id":-1}`)); err == nil {
		t.Fatal("negative numeric path field accepted")
	}
}

func TestValueValidatorsCoverSupportedAndUnsupportedForms(t *testing.T) {
	if !ValidSandboxImage("python:3.12") || ValidSandboxImage("bad image") || !ValidJobHardware("cpu-basic") || ValidJobHardware("root") {
		t.Fatal("sandbox validator mismatch")
	}
	if !ValidSpaceSDK("gradio") || ValidSpaceSDK("unknown") || !ValidVariableKey("MODE") || ValidVariableKey("BAD-KEY") {
		t.Fatal("space validator mismatch")
	}
	if !ValidGitRefComponent("release/v1") || ValidGitRefComponent("bad..ref") {
		t.Fatal("git ref validator mismatch")
	}
	if err := ValidateSandboxVolume(SandboxVolume{Type: "bucket", Source: "acme/data", MountPath: "/data"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSandboxVolume(SandboxVolume{Type: "shell", Source: "acme/data", MountPath: "/data"}); err == nil {
		t.Fatal("invalid sandbox volume accepted")
	}
	if (SandboxRef{Namespace: "acme", JobID: "job", LocalID: "local"}).ID() != "job.local" || (BucketRef{Namespace: "acme", Name: "data"}).ID() != "acme/data" || (SpaceRef{Owner: "acme", Name: "demo"}).ID() != "acme/demo" {
		t.Fatal("resource ID mismatch")
	}
}
