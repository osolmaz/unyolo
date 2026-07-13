package hubclient

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestUVJobTransformMatchesPinnedSDKShape(t *testing.T) {
	body, err := transformBoundBody("uv_job", json.RawMessage(`{
		"script":"https://example.com/train.py",
		"script_args":["--epochs","3"],
		"dependencies":["trl","datasets"],
		"python":"3.13",
		"environment":{"MODE":"test"},
		"secrets":{"TOKEN":"secret"},
		"timeout_seconds":300,
		"volumes":[{"type":"bucket","source":"acme/data","mount_path":"/data","read_only":true}],
		"expose":[8000],"ssh":true
	}`))
	if err != nil {
		t.Fatal(err)
	}
	job := body.(map[string]any)
	wantCommand := []string{"uv", "run", "--with", "trl", "--with", "datasets", "--python", "3.13", "https://example.com/train.py", "--epochs", "3"}
	if !reflect.DeepEqual(job["command"], wantCommand) || job["dockerImage"] != defaultUVImage || job["flavor"] != "cpu-basic" {
		t.Fatalf("job = %#v", job)
	}
	volumes := job["volumes"].([]map[string]any)
	if volumes[0]["mountPath"] != "/data" || volumes[0]["readOnly"] != true {
		t.Fatalf("volumes = %#v", volumes)
	}
}

func TestScheduledUVJobTransformWrapsJobSpec(t *testing.T) {
	body, err := transformBoundBody("uv_scheduled_job", json.RawMessage(`{"script":"lighteval","schedule":"@weekly","suspend":false,"concurrency":true}`))
	if err != nil {
		t.Fatal(err)
	}
	scheduled := body.(map[string]any)
	job := scheduled["jobSpec"].(map[string]any)
	if scheduled["schedule"] != "@weekly" || scheduled["suspend"] != false || scheduled["concurrency"] != true || !reflect.DeepEqual(job["command"], []string{"uv", "run", "lighteval"}) {
		t.Fatalf("scheduled = %#v", scheduled)
	}
}

func TestUVJobTransformRejectsLocalFilesAndUnknownTransforms(t *testing.T) {
	for _, test := range []struct {
		transform string
		arguments string
	}{
		{"uv_job", `{"script":"train.py"}`},
		{"uv_job", `{"script":"command","script_args":["config.yaml"]}`},
		{"missing", `{"script":"command"}`},
		{"uv_scheduled_job", `{"script":"command"}`},
	} {
		if _, err := transformBoundBody(test.transform, json.RawMessage(test.arguments)); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("transform %q accepted %s: %v", test.transform, test.arguments, err)
		}
	}
}
