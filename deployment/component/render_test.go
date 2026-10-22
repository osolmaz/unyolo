package component

import (
	"encoding/json"
	"testing"

	"github.com/osolmaz/unyolo/deployment/api"
)

func standardRenderRequest() (api.RenderRequest, []byte) {
	template := `{
  "api_version": "unyolo.io/github-deployment/v1",
  "accounts": [{"name": "gh-broker", "group": "gh-broker", "home": "/etc/gh-broker", "shell": "/usr/sbin/nologin"}],
  "groups": [
    {"name": "gh-broker-agent", "members": []},
    {"name": "gh-broker-operator", "members": []}
  ],
  "credentials": [
    {"slot": "github-agent-secret", "destination": "/etc/gh-broker/secrets", "mode": 384, "owner": "gh-broker", "group": "gh-broker", "encoding": "client_secret_file", "client_id": "agent"},
    {"slot": "github-operator-secret", "destination": "/etc/gh-broker/operator-secrets", "mode": 384, "owner": "gh-broker", "group": "gh-broker", "encoding": "client_secret_file", "client_id": "operator"}
  ],
  "clients": [
    {"agent_id": "agent", "broker_name": "gh-broker", "env_prefix": "GH_BROKER", "secret_slot": "github-agent-secret", "endpoint": "unix:///run/broker.sock"}
  ]
}`
	request := api.RenderRequest{
		APIVersion: api.RenderAPIVersion, ComponentID: "github", OperatingSystem: "linux", Architecture: "amd64", Profile: json.RawMessage(template),
		Approvers: []api.RenderApprover{{ID: "alice", Account: "alice"}},
		Connections: []api.RenderConnection{
			{ID: "bob", ClientID: "bob", Providers: []string{"github"}, TargetKind: "local_account", Isolation: "separate", UnixUser: "bob", Home: "/home/bob"},
		},
	}
	return request, []byte(template)
}

func TestStandardRendererDeterministicOutput(t *testing.T) {
	t.Parallel()
	request, template := standardRenderRequest()
	first, err := (StandardRenderer{}).Render(request, template, map[string][]byte{})
	if err != nil {
		t.Fatalf("Render() first: %v", err)
	}
	second, err := (StandardRenderer{}).Render(request, template, map[string][]byte{})
	if err != nil {
		t.Fatalf("Render() second: %v", err)
	}
	if first.RenderDigest != second.RenderDigest || string(first.Profile) != string(second.Profile) {
		t.Fatal("render output is not deterministic")
	}
	var profile Profile
	if err := json.Unmarshal(first.Profile, &profile); err != nil {
		t.Fatal(err)
	}
	if len(profile.SecretStores) != 2 || len(profile.Clients) != 1 || profile.Clients[0].AgentID != "bob" {
		t.Fatalf("rendered profile = %#v", profile)
	}
}

func TestStandardRendererDeliversOperatorCredentialsToManagedApprovers(t *testing.T) {
	t.Parallel()
	request, _ := standardRenderRequest()
	var template map[string]any
	if err := json.Unmarshal(request.Profile, &template); err != nil {
		t.Fatal(err)
	}
	template["operator_clients"] = []map[string]string{{
		"operator_id": "operator", "broker_name": "gh-broker", "secret_slot": "github-operator-secret", "endpoint": "unix:///run/operator.sock",
	}}
	data, err := json.Marshal(template)
	if err != nil {
		t.Fatal(err)
	}
	request.Profile = data
	request.Approvers = append(request.Approvers, api.RenderApprover{ID: "telegram", Account: "unyolo-telegram", Managed: true, Home: "/var/lib/unyolo-telegram"})
	response, err := (StandardRenderer{}).Render(request, data, map[string][]byte{})
	if err != nil {
		t.Fatal(err)
	}
	var profile Profile
	if err := json.Unmarshal(response.Profile, &profile); err != nil {
		t.Fatal(err)
	}
	want := OperatorClient{OperatorID: "telegram", BrokerName: "gh-broker", SecretSlot: "github-approver-telegram", Endpoint: "unix:///run/operator.sock"}
	if len(profile.OperatorClients) != 1 || profile.OperatorClients[0] != want {
		t.Fatalf("operator clients = %#v", profile.OperatorClients)
	}
	if members := profile.Groups[1].Members; len(members) != 2 || members[1] != "unyolo-telegram" {
		t.Fatalf("operator group members = %v", members)
	}
	request.Approvers = request.Approvers[:1]
	response, err = (StandardRenderer{}).Render(request, data, map[string][]byte{})
	if err != nil {
		t.Fatal(err)
	}
	profile = Profile{}
	if err := json.Unmarshal(response.Profile, &profile); err != nil || len(profile.OperatorClients) != 0 {
		t.Fatalf("operator clients without a managed approver = %#v, %v", profile.OperatorClients, err)
	}
}

func TestStandardRendererDigestBindsFilesAndPrompts(t *testing.T) {
	t.Parallel()
	request, template := standardRenderRequest()
	asset := map[string][]byte{"files/github/env": []byte("EXAMPLE=1\n")}
	response, err := (StandardRenderer{}).Render(request, template, asset)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Validate(); err != nil {
		t.Fatalf("render response is invalid: %v", err)
	}
	if len(response.Files) != 1 || response.Files[0].Path != "files/github/env" {
		t.Fatalf("render files = %#v", response.Files)
	}
	if len(response.SecretPrompts) == 0 || len(response.ReviewItems) == 0 {
		t.Fatalf("render prompts and review items should not be empty")
	}
}

func TestRewriteClientArraysHandlesInlineAndMultilineLists(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		"{\n  \"clients\": [\"agent\"],\n  \"allow\": true\n}\n",
		"{\n  \"clients\": [\n    \"agent\"\n  ],\n  \"allow\": true\n}\n",
	} {
		updated, err := rewriteClientArrays([]byte(input), []string{"alice", "bob"})
		if err != nil {
			t.Fatal(err)
		}
		var value struct {
			Clients []string `json:"clients"`
		}
		if err := json.Unmarshal(updated, &value); err != nil {
			t.Fatal(err)
		}
		if len(value.Clients) != 2 || value.Clients[0] != "alice" || value.Clients[1] != "bob" {
			t.Fatalf("rewritten clients = %#v", value.Clients)
		}
	}
}

func TestRenderRequestRejectsInvalidInputs(t *testing.T) {
	t.Parallel()
	request, _ := standardRenderRequest()
	original := request
	tests := []struct {
		name   string
		mutate func(*api.RenderRequest)
	}{
		{"identity", func(r *api.RenderRequest) { r.ComponentID = "" }},
		{"platform", func(r *api.RenderRequest) { r.OperatingSystem = "" }},
		{"approvers", func(r *api.RenderRequest) { r.Approvers = nil }},
		{"managed approver without home", func(r *api.RenderRequest) {
			r.Approvers = []api.RenderApprover{{ID: "telegram", Account: "unyolo-telegram", Managed: true}}
		}},
		{"home without managed approver", func(r *api.RenderRequest) {
			r.Approvers = []api.RenderApprover{{ID: "alice", Account: "alice", Home: "/home/alice"}}
		}},
		{"relative managed home", func(r *api.RenderRequest) {
			r.Approvers = []api.RenderApprover{{ID: "telegram", Account: "unyolo-telegram", Managed: true, Home: "var/lib"}}
		}},
		{"duplicate provider", func(r *api.RenderRequest) { r.Providers = []string{"github", "github"} }},
		{"invalid provider", func(r *api.RenderRequest) { r.Providers = []string{"Git Hub"} }},
		{"telegram chat", func(r *api.RenderRequest) { r.Telegram = &api.RenderTelegram{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := original
			test.mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatalf("Validate() accepted %s", test.name)
			}
		})
	}
}
