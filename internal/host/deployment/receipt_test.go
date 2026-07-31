package deployment

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/deployment/api"
	"github.com/osolmaz/unyolo/deployment/profile"
	"github.com/osolmaz/unyolo/internal/host/bundle"
	"github.com/osolmaz/unyolo/internal/host/identity"
)

func sampleReceipt() Receipt {
	return Receipt{
		APIVersion:         ReceiptAPIVersion,
		InstallationName:   "default",
		InstallationDigest: "sha256:" + strings.Repeat("a", 64),
		DeploymentName:     "default",
		DeploymentDigest:   "sha256:" + strings.Repeat("b", 64),
		RuntimeBundleID:    "engine-test",
		RecordedAt:         time.Now().UTC(),
		Accounts: []AccountReceipt{
			{ID: "bob", UnixUser: "bob", Mode: "existing", Home: "/home/bob", Shell: "/bin/bash", Created: false},
			{ID: "unyolo-agent", UnixUser: "unyolo-agent", Mode: "managed", Home: "/var/lib/unyolo-agent", Shell: "/usr/sbin/nologin", Created: true},
		},
		Services: []ServiceReceipt{
			{Name: "gh-broker.service", Component: "github"},
		},
		Connections: []ConnectionReceipt{
			{ID: "bob", ClientID: "bob"},
			{ID: "unyolo-agent", ClientID: "unyolo-agent"},
		},
		Components: []ComponentReceipt{
			{ID: "github", PlanDigest: "sha256:" + strings.Repeat("c", 64)},
		},
	}
}

func TestReceiptValidateAcceptsValidReceipt(t *testing.T) {
	t.Parallel()
	receipt := sampleReceipt()
	if err := receipt.Validate(); err != nil {
		t.Fatalf("valid receipt was rejected: %v", err)
	}
}

func TestReceiptValidateRejectsInvalid(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*Receipt){
		"missing api":               func(r *Receipt) { r.APIVersion = "" },
		"bad installation digest":   func(r *Receipt) { r.InstallationDigest = "abc" },
		"missing runtime":           func(r *Receipt) { r.RuntimeBundleID = "" },
		"missing recorded time":     func(r *Receipt) { r.RecordedAt = time.Time{} },
		"bad account mode":          func(r *Receipt) { r.Accounts[0].Mode = "extra" },
		"duplicate connection":      func(r *Receipt) { r.Connections = append(r.Connections, r.Connections[0]) },
		"duplicate service":         func(r *Receipt) { r.Services = append(r.Services, r.Services[0]) },
		"non-absolute home":         func(r *Receipt) { r.Accounts[0].Home = "home/bob" },
		"empty component id":        func(r *Receipt) { r.Components[0].ID = "" },
		"bad component plan digest": func(r *Receipt) { r.Components[0].PlanDigest = "abc" },
		"duplicate component id":    func(r *Receipt) { r.Components = append(r.Components, r.Components[0]) },
		"invalid installation name": func(r *Receipt) { r.InstallationName = "BAD NAME" },
	}
	for name, mutate := range cases {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			receipt := sampleReceipt()
			mutate(&receipt)
			if err := receipt.Validate(); err == nil {
				t.Fatalf("invalid receipt was accepted: %s", name)
			}
		})
	}
}

func TestReceiptRoundTrip(t *testing.T) {
	t.Parallel()
	receipt := sampleReceipt()
	state := t.TempDir()
	if err := SaveReceipt(state, receipt); err != nil {
		t.Fatalf("SaveReceipt() = %v", err)
	}
	loaded, found, err := LoadReceipt(state)
	if err != nil || !found {
		t.Fatalf("LoadReceipt() = %v, found=%v", err, found)
	}
	if loaded.InstallationDigest != receipt.InstallationDigest {
		t.Fatalf("installation digest = %q", loaded.InstallationDigest)
	}
	if err := DeleteReceipt(state); err != nil {
		t.Fatalf("DeleteReceipt() = %v", err)
	}
	if _, found, err := LoadReceipt(state); err != nil || found {
		t.Fatalf("Load after Delete = %v, found=%v", err, found)
	}
}

func TestReceiptRejectsSecretLikeUnknownFields(t *testing.T) {
	t.Parallel()
	receipt := sampleReceipt()
	data, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), `"api_version"`, `"secret":"forbidden","api_version"`, 1)
	state := t.TempDir()
	path := filepath.Join(state, receiptFilename)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadReceipt(state); err == nil {
		t.Fatal("receipt containing unknown fields was accepted")
	}
}

func TestReceiptFromPlanCollectsAgentsAndServices(t *testing.T) {
	t.Parallel()
	planned := Planned{
		Snapshot: profile.Snapshot{
			Deployment: profile.Deployment{
				Name:               "default",
				InstallationDigest: "sha256:" + strings.Repeat("d", 64),
				Agents: []profile.Agent{
					{ID: "bob", ClientID: "bob", Target: profile.AgentTarget{Kind: "local_account", Isolation: "separate", AccountMode: "existing", UnixUser: "bob", Home: "/home/bob", Shell: "/bin/bash"}},
					{ID: "unyolo-agent", ClientID: "unyolo-agent", Target: profile.AgentTarget{Kind: "local_account", Isolation: "separate", AccountMode: "managed", UnixUser: "unyolo-agent", Home: "/var/lib/unyolo-agent", Shell: "/usr/sbin/nologin"}},
				},
			},
			Digest: "sha256:" + strings.Repeat("e", 64),
			Manifest: bundle.Manifest{
				BundleID: "engine-test",
				Components: []bundle.Component{
					{Name: "github", Services: []string{"gh-broker.service", "gh-broker.socket"}},
				},
			},
		},
		Accounts: map[string]identity.Account{
			"agent:bob":          {Name: "bob"},
			"agent:unyolo-agent": {Missing: true},
		},
		Responses: []api.Response{{ComponentID: "github", PlanDigest: "sha256:" + strings.Repeat("f", 64)}},
	}
	// Also add a component to the deployment so components populate.
	planned.Snapshot.Deployment.Components = []profile.Component{{ID: "github"}}
	receipt, err := ReceiptFromPlan(planned, "default", time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatalf("ReceiptFromPlan() = %v", err)
	}
	if len(receipt.Accounts) != 2 {
		t.Fatalf("accounts = %#v", receipt.Accounts)
	}
	created := false
	for _, account := range receipt.Accounts {
		if account.ID == "unyolo-agent" {
			created = account.Created
		}
		if account.ID == "bob" && account.Created {
			t.Fatalf("existing account marked created: %#v", account)
		}
	}
	if !created {
		t.Fatal("managed missing account was not marked created")
	}
	if len(receipt.Services) != 2 || receipt.Services[0].Component != "github" {
		t.Fatalf("services = %#v", receipt.Services)
	}
	if len(receipt.Connections) != 2 || len(receipt.Components) != 1 {
		t.Fatalf("connections/components = %#v %#v", receipt.Connections, receipt.Components)
	}
}
