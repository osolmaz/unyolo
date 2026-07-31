package api

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestRequestValidate(t *testing.T) {
	valid := Request{
		APIVersion: APIVersion, Action: ActionPlan,
		DeploymentDigest: fixedDigest("a"), ComponentID: "github",
		Profile: []byte(`{"api_version":"test"}`),
		Files:   []File{{Path: "policy.json", SHA256: digestBytes([]byte("policy")), Data: []byte("policy")}},
		Agents:  []AgentBinding{{ID: "agent", ClientID: "client", TargetKind: "local_account", Isolation: "separate", AccountMode: "existing", UnixUser: "agent", Home: "/home/agent"}},
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		edit func(*Request)
	}{
		{"version", func(value *Request) { value.APIVersion = "old" }},
		{"action", func(value *Request) { value.Action = "unknown" }},
		{"deployment digest", func(value *Request) { value.DeploymentDigest = "bad" }},
		{"component", func(value *Request) { value.ComponentID = "" }},
		{"profile", func(value *Request) { value.Profile = nil }},
		{"file path", func(value *Request) { value.Files[0].Path = "" }},
		{"file digest", func(value *Request) { value.Files[0].SHA256 = "bad" }},
		{"file mismatch", func(value *Request) { value.Files[0].Data = []byte("changed") }},
		{"agent", func(value *Request) { value.Agents[0].ID = "" }},
		{"secret fd", func(value *Request) { value.Secrets = []SecretDescriptor{{Name: "slot", FD: 2}} }},
		{"apply digest", func(value *Request) { value.Action = ActionApply }},
		{"rollback handle", func(value *Request) { value.Action = ActionRollback; value.PlanDigest = fixedDigest("c") }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			value := valid
			value.Files = append([]File(nil), valid.Files...)
			value.Agents = append([]AgentBinding(nil), valid.Agents...)
			test.edit(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("invalid request was accepted")
			}
		})
	}
}

func TestResponseValidate(t *testing.T) {
	valid := Response{
		APIVersion: APIVersion, ComponentID: "github", Status: "planned", PlanDigest: fixedDigest("a"),
		Actions: []PlannedAction{{
			ID: "policy", Type: "write", Risk: "medium",
			Resource:      Resource{Kind: "file", ID: "/etc/gh-broker/scope.json"},
			DesiredDigest: fixedDigest("b"), CurrentDigest: fixedDigest("c"),
		}},
		Credentials: []CredentialAction{{Slot: "secret", Action: "install"}},
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		edit func(*Response)
	}{
		{"version", func(value *Response) { value.APIVersion = "old" }},
		{"component", func(value *Response) { value.ComponentID = "" }},
		{"status", func(value *Response) { value.Status = "bad" }},
		{"digest", func(value *Response) { value.PlanDigest = "bad" }},
		{"action id", func(value *Response) { value.Actions[0].ID = "" }},
		{"action type", func(value *Response) { value.Actions[0].Type = "" }},
		{"risk", func(value *Response) { value.Actions[0].Risk = "extreme" }},
		{"resource", func(value *Response) { value.Actions[0].Resource.Kind = "" }},
		{"desired", func(value *Response) { value.Actions[0].DesiredDigest = "bad" }},
		{"current", func(value *Response) { value.Actions[0].CurrentDigest = "bad" }},
		{"credential", func(value *Response) { value.Credentials[0].Slot = "" }},
		{"credential action", func(value *Response) { value.Credentials[0].Action = "delete" }},
		{"rollback", func(value *Response) { value.RollbackHandle = strings.Repeat("x", 129) }},
		{"verification", func(value *Response) { value.Verification = []string{""} }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			value := valid
			value.Actions = append([]PlannedAction(nil), valid.Actions...)
			value.Credentials = append([]CredentialAction(nil), valid.Credentials...)
			test.edit(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("invalid response was accepted")
			}
		})
	}
}

func TestDigestValidation(t *testing.T) {
	for _, value := range []string{"", "sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("0", 63), "md5:" + strings.Repeat("0", 64)} {
		if validDigest(value) {
			t.Fatalf("validDigest(%q) = true", value)
		}
	}
}

func fixedDigest(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}

func digestBytes(value []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(value))
}
