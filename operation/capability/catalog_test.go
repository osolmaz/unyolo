package capability

import (
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/authorization/budget"
)

func TestValidateAcceptsProviderCatalog(t *testing.T) {
	tool, command := "gh_repo_delete", "repo delete"
	values := []Descriptor{{
		Name: "repo.delete", OperationRevision: 1, Disposition: "E/X",
		DefaultAuthorizationMode: ModeWindow, AuthorizationModes: []AuthorizationMode{ModeWindow, ModeExecution}, ExplicitOnly: true,
		Implementation: StatusImplemented, Risk: RiskCritical, TargetKind: "repo",
		MaxUses: 2, RequestTTLSeconds: 300, ApprovalTTLSeconds: 300,
		AgentFacing: true, MCPTool: &tool, CLICommand: &command,
	}}
	if err := Validate(values, ValidationOptions{Provider: "GitHub", ExpectedCount: 1, MCPToolPrefix: "gh_"}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsStructuralDrift(t *testing.T) {
	tool, command := "hf_repo_delete", "repo delete"
	valid := Descriptor{
		Name: "repo.delete", OperationRevision: 1, Disposition: "E/X",
		DefaultAuthorizationMode: ModeWindow, AuthorizationModes: []AuthorizationMode{ModeWindow, ModeExecution}, ExplicitOnly: true,
		Implementation: StatusImplemented, Risk: RiskCritical, TargetKind: "repo",
		MaxUses: 2, RequestTTLSeconds: 300, ApprovalTTLSeconds: 300,
		AgentFacing: true, MCPTool: &tool, CLICommand: &command,
	}
	tests := map[string]func(*Descriptor){
		"identity":        func(value *Descriptor) { value.Name = "delete" },
		"revision":        func(value *Descriptor) { value.OperationRevision = 2 },
		"default mode":    func(value *Descriptor) { value.DefaultAuthorizationMode = "other" },
		"allowed modes":   func(value *Descriptor) { value.AuthorizationModes = []AuthorizationMode{ModeWindow} },
		"status":          func(value *Descriptor) { value.Implementation = "other" },
		"risk":            func(value *Descriptor) { value.Risk = "" },
		"target":          func(value *Descriptor) { value.TargetKind = "bad-target" },
		"ttl":             func(value *Descriptor) { value.RequestTTLSeconds = 0 },
		"uses":            func(value *Descriptor) { value.MaxUses = 1 },
		"disposition":     func(value *Descriptor) { value.Disposition = "E" },
		"family glob":     func(value *Descriptor) { value.FamilyGlobAllowed = true },
		"tool prefix":     func(value *Descriptor) { wrong := "github_repo_delete"; value.MCPTool = &wrong },
		"missing command": func(value *Descriptor) { value.CLICommand = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := valid
			mutate(&value)
			if err := Validate([]Descriptor{value}, ValidationOptions{Provider: "HF", ExpectedCount: 1, MCPToolPrefix: "hf_"}); err == nil {
				t.Fatal("Validate accepted drift")
			}
		})
	}
}

func TestValidateAcceptsMaximumFiniteWindowBudget(t *testing.T) {
	tool, command := "hf_bucket_write", "bucket write"
	value := Descriptor{Name: "bucket.write", OperationRevision: 1, Disposition: "W",
		DefaultAuthorizationMode: ModeWindow, AuthorizationModes: []AuthorizationMode{ModeWindow, ModeExecution},
		Implementation: StatusImplemented, Risk: RiskHigh, TargetKind: "bucket", MaxUses: int(usebudget.MaxFiniteUses),
		RequestTTLSeconds: 300, ApprovalTTLSeconds: 604800, AgentFacing: true, MCPTool: &tool, CLICommand: &command}
	options := ValidationOptions{Provider: "HF", ExpectedCount: 1, MCPToolPrefix: "hf_"}
	if err := Validate([]Descriptor{value}, options); err != nil {
		t.Fatal(err)
	}
	value.MaxUses++
	if err := Validate([]Descriptor{value}, options); err == nil {
		t.Fatal("Validate accepted a window budget above the global maximum")
	}
}

func TestValidateRejectsCatalogAndOptionDrift(t *testing.T) {
	if err := Validate(nil, ValidationOptions{}); err == nil {
		t.Fatal("Validate accepted empty options")
	}
	tool, command := "gh_repo_read", "repo read"
	value := Descriptor{Name: "repo.read", OperationRevision: 1, Disposition: "W",
		DefaultAuthorizationMode: ModeWindow, AuthorizationModes: []AuthorizationMode{ModeWindow, ModeExecution},
		Implementation: StatusImplemented, Risk: RiskLow, TargetKind: "repo", MaxUses: 2,
		RequestTTLSeconds: 300, ApprovalTTLSeconds: 300, AgentFacing: true, MCPTool: &tool, CLICommand: &command}
	options := ValidationOptions{Provider: "GitHub", ExpectedCount: 2, MCPToolPrefix: "gh_"}
	if err := Validate([]Descriptor{value}, options); err == nil || !strings.Contains(err.Error(), "want 2") {
		t.Fatalf("count error = %v", err)
	}
	options.ExpectedCount = 2
	if err := Validate([]Descriptor{value, value}, options); err == nil {
		t.Fatal("Validate accepted duplicate descriptors")
	}
}
