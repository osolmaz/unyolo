//go:build linux

package deployment

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/osolmaz/unyolo/deployment/api"
	componentprofile "github.com/osolmaz/unyolo/deployment/component"
	"github.com/osolmaz/unyolo/internal/host/bundle"
)

func TestPlanStaleClientsSelectsOnlyUnchangedGeneratedFiles(t *testing.T) {
	t.Parallel()
	state := t.TempDir()
	engine := &Engine{options: Options{Paths: bundle.Paths{Root: t.TempDir(), StateDir: state}}}
	path := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(path, []byte("generated"), 0o600); err != nil {
		t.Fatal(err)
	}
	receipt := sampleReceipt()
	receipt.Resources = []ResourceReceipt{{ComponentID: "github", ActionID: "client-bob", Kind: "client", ID: "bob", Path: path, Created: true,
		Fingerprint: componentprofile.ResourceFingerprint(t.Context(), api.Resource{Kind: "client", ID: "bob", Path: path}, true)}}
	if err := SaveReceipt(state, receipt); err != nil {
		t.Fatal(err)
	}
	stale, response, err := engine.planStaleClients(t.Context(), nil)
	if err != nil || len(stale) != 1 || response == nil || len(response.Actions) != 1 {
		t.Fatalf("stale plan = %#v, %#v, %v", stale, response, err)
	}
	if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	stale, response, err = engine.planStaleClients(t.Context(), nil)
	if err != nil || len(stale) != 0 || response != nil {
		t.Fatalf("changed client was selected: %#v, %#v, %v", stale, response, err)
	}
}

func TestStaleClientQuarantineRollbackAndFinalize(t *testing.T) {
	t.Parallel()
	state := t.TempDir()
	engine := &Engine{options: Options{Paths: bundle.Paths{Root: t.TempDir(), StateDir: state}}}
	path := filepath.Join(t.TempDir(), "client.json")
	body := []byte("private generated client configuration\n")
	write := func() ResourceReceipt {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return ResourceReceipt{ComponentID: "github", ActionID: "client-bob", Kind: "client", ID: "bob", Path: path, Created: true,
			Fingerprint: componentprofile.ResourceFingerprint(t.Context(), api.Resource{Kind: "client", ID: "bob", Path: path}, true)}
	}
	resource := write()
	handle, err := engine.quarantineStaleClient(t.Context(), resource)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("client remains after quarantine: %v", err)
	}
	if err := engine.restoreStaleClient(t.Context(), handle); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(body) {
		t.Fatalf("restored client = %q, %v", got, err)
	}

	resource = write()
	handle, err = engine.quarantineStaleClient(t.Context(), resource)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.discardStaleClientBackup(handle); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("client remains after finalize: %v", err)
	}
	metadata, err := cleanupMetadataPath(state, handle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(metadata); !os.IsNotExist(err) {
		t.Fatalf("cleanup metadata remains: %v", err)
	}
}

func TestStaleClientQuarantineRejectsChangedContent(t *testing.T) {
	t.Parallel()
	engine := &Engine{options: Options{Paths: bundle.Paths{Root: t.TempDir(), StateDir: t.TempDir()}}}
	path := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	resource := ResourceReceipt{ComponentID: "github", ActionID: "client-bob", Kind: "client", ID: "bob", Path: path, Created: true,
		Fingerprint: componentprofile.ResourceFingerprint(t.Context(), api.Resource{Kind: "client", ID: "bob", Path: path}, true)}
	if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.quarantineStaleClient(t.Context(), resource); err == nil {
		t.Fatal("changed client configuration was quarantined")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "changed" {
		t.Fatalf("changed client was touched: %q, %v", got, err)
	}
}
