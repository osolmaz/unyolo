package hubclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRepositoryRefsAndSpaceAdministrationCalls(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/whoami-v2":
			_, _ = io.WriteString(w, `{"name":"acme"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/repos/create":
			_, _ = io.WriteString(w, `{"url":"https://huggingface.co/acme/demo"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/models/acme/demo/refs":
			_, _ = io.WriteString(w, `{"branches":[{"name":"main","ref":"refs/heads/main","targetCommit":"abc"}],"tags":[{"name":"v1","ref":"refs/tags/v1","targetCommit":"abc"}]}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/spaces/acme/demo/variables":
			_, _ = io.WriteString(w, `{"MODE":{"value":"test","description":"runtime mode"}}`)
		case r.URL.Path == "/api/spaces/acme/demo/runtime" || r.URL.Path == "/api/spaces/acme/demo/restart" || r.URL.Path == "/api/spaces/acme/demo/pause" || r.URL.Path == "/api/spaces/acme/demo/hardware" || r.URL.Path == "/api/spaces/acme/demo/sleeptime" || r.URL.Path == "/api/spaces/acme/demo/dev-mode":
			_, _ = io.WriteString(w, `{"stage":"RUNNING","hardware":{"current":"cpu-basic","requested":"cpu-basic"},"gcTimeout":600,"devMode":true}`)
		case r.Method == http.MethodPut && r.URL.Path == "/api/models/acme/demo/settings":
			_, _ = io.WriteString(w, `{"visibility":"private"}`)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, "secret", WithHTTPTransport(server.Client().Transport))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ref := RepoRef{Type: RepoTypeModel, Owner: "acme", Name: "demo"}
	space := SpaceRef{Owner: "acme", Name: "demo"}
	if identity, err := client.WhoAmI(ctx); err != nil || identity.Name != "acme" {
		t.Fatalf("WhoAmI() = %+v, %v", identity, err)
	}
	if created, err := client.CreateRepo(ctx, CreateRepoInput{Ref: ref, Visibility: VisibilityPrivate, PersonalNamespace: true}); err != nil || created.URL == "" {
		t.Fatalf("CreateRepo() = %+v, %v", created, err)
	}
	for name, call := range map[string]func() error{
		"move":          func() error { return client.MoveRepo(ctx, ref, "acme", "renamed") },
		"gating":        func() error { return client.UpdateRepoGating(ctx, ref, GatedManual) },
		"branch create": func() error { return client.CreateBranch(ctx, ref, "feature", "main") },
		"branch delete": func() error { return client.DeleteBranch(ctx, ref, "feature") },
		"tag create":    func() error { return client.CreateTag(ctx, ref, "v2", "release", "main") },
		"tag delete":    func() error { return client.DeleteTag(ctx, ref, "v1") },
		"variable set":  func() error { return client.SetSpaceVariable(ctx, space, "MODE", "test", "runtime mode") },
		"variable del":  func() error { return client.DeleteSpaceVariable(ctx, space, "MODE") },
	} {
		if err := call(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if settings, err := client.UpdateRepoVisibility(ctx, ref, VisibilityPrivate); err != nil || settings.Visibility != VisibilityPrivate {
		t.Fatalf("UpdateRepoVisibility() = %+v, %v", settings, err)
	}
	refs, err := client.ListRefs(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	if branch, found := refs.Branch("main"); !found || branch.TargetCommit != "abc" {
		t.Fatalf("Branch(main) = %+v, %v", branch, found)
	}
	if tag, found := refs.Tag("v1"); !found || tag.TargetCommit != "abc" {
		t.Fatalf("Tag(v1) = %+v, %v", tag, found)
	}
	for name, call := range map[string]func() (SpaceRuntime, error){
		"read":     func() (SpaceRuntime, error) { return client.SpaceRuntime(ctx, space) },
		"restart":  func() (SpaceRuntime, error) { return client.RestartSpace(ctx, space, true) },
		"pause":    func() (SpaceRuntime, error) { return client.PauseSpace(ctx, space) },
		"hardware": func() (SpaceRuntime, error) { return client.RequestSpaceHardware(ctx, space, "cpu-basic", nil) },
		"sleep":    func() (SpaceRuntime, error) { return client.SetSpaceSleepTime(ctx, space, 600) },
		"dev mode": func() (SpaceRuntime, error) { return client.SetSpaceDevMode(ctx, space, true) },
	} {
		runtime, err := call()
		if err != nil || runtime.Stage != "RUNNING" {
			t.Fatalf("%s runtime = %+v, %v", name, runtime, err)
		}
	}
	if variables, err := client.SpaceVariables(ctx, space); err != nil || variables["MODE"].Value != "test" {
		t.Fatalf("SpaceVariables() = %+v, %v", variables, err)
	}
}
