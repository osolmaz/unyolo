package container

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeRunner struct {
	stdout []byte
	stderr []byte
	err    error
	dir    string
	args   []string
}

func (f *fakeRunner) Run(_ context.Context, dir string, args ...string) ([]byte, []byte, error) {
	f.dir = dir
	f.args = append([]string(nil), args...)
	return f.stdout, f.stderr, f.err
}

func TestProjectOptionsValidate(t *testing.T) {
	cases := []struct {
		name    string
		options ProjectOptions
		wantErr bool
	}{
		{"absolute clean directory", ProjectOptions{Directory: "/srv/agent"}, false},
		{"relative directory rejected", ProjectOptions{Directory: "agent"}, true},
		{"non-clean directory rejected", ProjectOptions{Directory: "/srv/../srv/agent"}, true},
		{"project name valid", ProjectOptions{Directory: "/srv/agent", ProjectName: "my-agent"}, false},
		{"project name invalid", ProjectOptions{Directory: "/srv/agent", ProjectName: "MyAgent"}, true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.options.Validate()
			if (err != nil) != testCase.wantErr {
				t.Fatalf("Validate() err=%v wantErr=%v", err, testCase.wantErr)
			}
		})
	}
}

func TestInspectParsesServices(t *testing.T) {
	stdout := []byte(`{
	  "name": "demo",
	  "services": {
	    "agent": {"image": "example/agent:1.0@sha256:` + strings.Repeat("a", 64) + `",
	      "volumes": [{"type":"bind","source":"/etc/example","target":"/etc/example"}]}
	  }
	}`)
	runner := &fakeRunner{stdout: stdout}
	project, err := Inspect(context.Background(), runner, ProjectOptions{Directory: "/srv/agent"})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if project.Name != "demo" || len(project.Services) != 1 {
		t.Fatalf("unexpected project: %+v", project)
	}
	if runner.dir != "/srv/agent" || runner.args[0] != "compose" {
		t.Fatalf("runner not invoked as expected: dir=%q args=%v", runner.dir, runner.args)
	}
}

func TestInspectFailsOnRunnerError(t *testing.T) {
	runner := &fakeRunner{err: errors.New("boom")}
	if _, err := Inspect(context.Background(), runner, ProjectOptions{Directory: "/srv/agent"}); err == nil {
		t.Fatal("expected runner error to propagate")
	}
}

func TestInspectRejectsHugeOutput(t *testing.T) {
	runner := &fakeRunner{stdout: make([]byte, MaxComposeConfigBytes+1)}
	if _, err := Inspect(context.Background(), runner, ProjectOptions{Directory: "/srv/agent"}); err == nil {
		t.Fatal("expected size error")
	}
}

func TestParseMountString(t *testing.T) {
	mount, err := parseMountString("/etc/example:/etc/example:ro")
	if err != nil {
		t.Fatalf("parseMountString: %v", err)
	}
	if mount.Type != "bind" || mount.Source != "/etc/example" || mount.Target != "/etc/example" {
		t.Fatalf("unexpected mount: %+v", mount)
	}
	if _, err := parseMountString("bad"); err == nil {
		t.Fatal("expected error on malformed mount string")
	}
}
