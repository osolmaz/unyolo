package intent

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIntentGoals(t *testing.T) {
	t.Parallel()
	values := []Intent{
		{APIVersion: APIVersion, Goal: GoalCommandOnly},
		{APIVersion: APIVersion, Goal: GoalCredentialService, CredentialService: &CredentialService{Location: ServiceNative, Providers: []string{"github"}}},
		{APIVersion: APIVersion, Goal: GoalAgentConnection, Agent: &Agent{Location: AgentLocalAccount, ConnectionName: "bob", Account: &Account{Mode: AccountExisting, Name: "bob"}}, Connection: &Connection{Transport: TransportLocalSocket}, Integrations: []string{"openclaw"}},
		{APIVersion: APIVersion, Goal: GoalCompleteLocal, CredentialService: &CredentialService{Location: ServiceDocker, Providers: []string{"github", "huggingface"}}, Agent: &Agent{Location: AgentContainer, ConnectionName: "agent", Container: &Container{ProjectDirectory: "/srv/app", Service: "agent"}}, Connection: &Connection{Transport: TransportTLS, RemoteEndpoint: "https://broker.example", ServerName: "broker.example"}},
	}
	for _, value := range values {
		value := value
		t.Run(string(value.Goal), func(t *testing.T) {
			t.Parallel()
			if err := value.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Decode(data); err != nil {
				t.Fatalf("Decode: %v", err)
			}
		})
	}
}

func TestIntentRejectsInvalidCrossFields(t *testing.T) {
	t.Parallel()
	cases := map[string]Intent{
		"missing service":        {APIVersion: APIVersion, Goal: GoalCredentialService},
		"service on command":     {APIVersion: APIVersion, Goal: GoalCommandOnly, CredentialService: &CredentialService{Location: ServiceNative, Providers: []string{"github"}}},
		"duplicate providers":    {APIVersion: APIVersion, Goal: GoalCredentialService, CredentialService: &CredentialService{Location: ServiceNative, Providers: []string{"github", "github"}}},
		"current named":          {APIVersion: APIVersion, Goal: GoalAgentConnection, Agent: &Agent{Location: AgentLocalAccount, ConnectionName: "bob", Account: &Account{Mode: AccountCurrent, Name: "root"}}, Connection: &Connection{Transport: TransportLocalSocket}},
		"plaintext remote":       {APIVersion: APIVersion, Goal: GoalAgentConnection, Agent: &Agent{Location: AgentRemote, ConnectionName: "bob"}, Connection: &Connection{Transport: TransportTLS, RemoteEndpoint: "http://host", ServerName: "host"}},
		"integration on command": {APIVersion: APIVersion, Goal: GoalCommandOnly, Integrations: []string{"openclaw"}},
	}
	for name, value := range cases {
		value := value
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := value.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestDecodeRejectsUnknownAndSecretFields(t *testing.T) {
	t.Parallel()
	for _, document := range []string{
		`{"api_version":"unyolo.io/setup-intent/v1","goal":"command_only","token":"secret"}`,
		`{"api_version":"unyolo.io/setup-intent/v1","goal":"command_only"} trailing`,
	} {
		if _, err := Decode([]byte(document)); err == nil {
			t.Fatalf("expected rejection for %s", document)
		}
	}
	oversized := []byte(`{"api_version":"unyolo.io/setup-intent/v1","goal":"command_only","x":"` + strings.Repeat("a", MaxDocumentSize) + `"}`)
	if _, err := Decode(oversized); err == nil {
		t.Fatal("expected size rejection")
	}
}
