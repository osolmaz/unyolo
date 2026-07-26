package privilege

import (
	"bytes"
	"io"
	"testing"

	"github.com/osolmaz/brokerkit/deployment/api"
	deploymentplan "github.com/osolmaz/brokerkit/deployment/plan"
	deploymentruntime "github.com/osolmaz/brokerkit/deployment/runtime"
)

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

func TestRequiredSecretSlotsIsStable(t *testing.T) {
	value := testWorkerPlan()
	got := RequiredSecretSlots(value)
	if len(got) != 2 || got[0] != "alpha" || got[1] != "zeta" {
		t.Fatalf("RequiredSecretSlots() = %v", got)
	}
}
