package opbinding

import (
	"slices"
	"testing"
)

func TestBindingsArePinnedAndSplitBroadRepositoryUpdate(t *testing.T) {
	values, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1152 {
		t.Fatalf("bindings=%d", len(values))
	}
	for _, operation := range []string{"repo.description.update", "repo.visibility.update", "repo.default_branch.update", "repo.feature.update"} {
		bindings := ByOperation(operation)
		if len(bindings) != 1 || bindings[0].UpstreamOperationID != "repos/update" || bindings[0].Method != "PATCH" {
			t.Fatalf("%s bindings=%+v", operation, bindings)
		}
	}
}

func TestBindingNeverAcceptsRawTransportSelectors(t *testing.T) {
	values, err := All()
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		for _, parameter := range value.ArgumentParameters {
			switch parameter.Name {
			case "method", "graphql", "caller", "headers":
				t.Fatalf("unsafe parameter in %s", value.ID)
			}
		}
	}
}

func TestBindingsSeparateSelfUsersFromExplicitUsersAndNumbersFromIDs(t *testing.T) {
	t.Parallel()
	for operation, want := range map[string]bool{
		"member.users_get_authenticated":    true,
		"member.users_update_authenticated": true,
		"member.users_block":                false,
		"member.users_get_by_username":      false,
	} {
		bindings := ByOperation(operation)
		if len(bindings) != 1 || bindings[0].AuthenticatedUserTarget != want {
			t.Fatalf("%s authenticated-user binding = %+v, want %t", operation, bindings, want)
		}
	}
	for _, operation := range []string{"issue.issues_update", "code_scanning.code_scanning_get_alert"} {
		bindings := ByOperation(operation)
		if len(bindings) != 1 || !slices.Contains(bindings[0].TargetPathParameters, TargetParameter{Name: pathNumberParameter(operation), Field: "number"}) {
			t.Fatalf("%s number binding = %+v", operation, bindings)
		}
	}
}

func TestBindingsUseDistinctAuthoritativeTargetFields(t *testing.T) {
	t.Parallel()
	organization := ByOperation("member.orgs_update_membership_for_authenticated_user")
	if len(organization) != 1 || !slices.Contains(organization[0].TargetPathParameters, TargetParameter{Name: "org", Field: "name"}) {
		t.Fatalf("organization binding = %+v", organization)
	}
	environment := ByOperation("environment.repos_create_or_update_environment")
	want := []TargetParameter{{Name: "owner", Field: "owner"}, {Name: "repo", Field: "repo"}, {Name: "environment_name", Field: "name"}}
	if len(environment) != 1 || !slices.Equal(environment[0].TargetPathParameters, want) {
		t.Fatalf("environment binding = %+v, want %+v", environment, want)
	}
}

func TestBindingsAuthorizeEveryNonTargetPathSelector(t *testing.T) {
	t.Parallel()
	binding := ByOperation("collaborator.orgs_remove_outside_collaborator")
	want := []AuthorizationParameter{{Name: "username", Attribute: "selector_username"}}
	if len(binding) != 1 || !slices.Equal(binding[0].AuthorizationParameters, want) {
		t.Fatalf("collaborator authorization parameters = %+v, want %+v", binding, want)
	}
	if attributes := AuthorizationAttributes("collaborator.orgs_remove_outside_collaborator"); !slices.Equal(attributes, []string{"selector_username"}) {
		t.Fatalf("authorization attributes = %v", attributes)
	}
	if attributes := AuthorizationAttributes("not.real"); attributes != nil {
		t.Fatalf("unknown authorization attributes = %v", attributes)
	}
	for _, binding := range mustBindings(t) {
		if err := validatePathAuthorization(binding); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPathAuthorizationValidationRejectsIncompleteBindings(t *testing.T) {
	base := ByOperation("collaborator.orgs_remove_outside_collaborator")[0]
	for name, mutate := range map[string]func(*Binding){
		"missing selector": func(value *Binding) { value.AuthorizationParameters = nil },
		"unknown path":     func(value *Binding) { value.AuthorizationParameters[0].Name = "not_in_path" },
		"target overlap":   func(value *Binding) { value.AuthorizationParameters[0].Name = "org" },
		"unsafe attr":      func(value *Binding) { value.AuthorizationParameters[0].Attribute = "username" },
		"duplicate name": func(value *Binding) {
			value.AuthorizationParameters = append(value.AuthorizationParameters, value.AuthorizationParameters[0])
		},
		"duplicate attr": func(value *Binding) {
			value.PathParameters = append(value.PathParameters, "actor")
			value.AuthorizationParameters = append(value.AuthorizationParameters, AuthorizationParameter{Name: "actor", Attribute: "selector_username"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			value.PathParameters = slices.Clone(base.PathParameters)
			value.TargetPathParameters = slices.Clone(base.TargetPathParameters)
			value.AuthorizationParameters = slices.Clone(base.AuthorizationParameters)
			mutate(&value)
			if err := validatePathAuthorization(value); err == nil {
				t.Fatal("invalid authorization binding accepted")
			}
		})
	}
}

func mustBindings(t *testing.T) []Binding {
	t.Helper()
	bindings, err := All()
	if err != nil {
		t.Fatal(err)
	}
	return bindings
}

func pathNumberParameter(operation string) string {
	if operation == "issue.issues_update" {
		return "issue_number"
	}
	return "alert_number"
}

func TestBindingValidationFailsClosed(t *testing.T) {
	valid, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(valid[:len(valid)-1]); err == nil {
		t.Fatal("short binding set accepted")
	}
	tests := []struct {
		name   string
		mutate func(*Binding)
	}{
		{"duplicate", func(value *Binding) { value.ID = valid[1].ID }},
		{"method", func(value *Binding) { value.Method = "TRACE" }},
		{"path", func(value *Binding) { value.PathTemplate = "relative" }},
		{"version", func(value *Binding) { value.APIVersion = "latest" }},
		{"limit", func(value *Binding) { value.RequestBytesLimit = 0 }},
		{"missing status", func(value *Binding) { value.SuccessStatusCodes = nil }},
		{"unsorted status", func(value *Binding) { value.SuccessStatusCodes = []int{204, 200} }},
		{"invalid status", func(value *Binding) { value.SuccessStatusCodes = []int{400} }},
		{"url", func(value *Binding) { value.PathTemplate = "https://example.invalid" }},
		{"missing response projection", func(value *Binding) { value.ResponseProjection = nil }},
		{"unsafe response projection", func(value *Binding) { value.ResponseProjection = []string{"token"} }},
		{"missing absence proof", func(value *Binding) { value.Reconciliation = "absence-proof"; value.ReconciliationBindingID = "" }},
		{"unexpected proof", func(value *Binding) { value.Reconciliation = "none"; value.ReconciliationBindingID = valid[0].ID }},
		{"parameter location", func(value *Binding) { value.ArgumentParameters = []Parameter{{Name: "page", In: "header"}} }},
		{"raw parameter", func(value *Binding) { value.ArgumentParameters = []Parameter{{Name: "method", In: "query"}} }},
		{"authenticated user ownership", func(value *Binding) { value.AuthenticatedUserTarget = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := slices.Clone(valid)
			test.mutate(&values[0])
			if err := Validate(values); err == nil {
				t.Fatal("invalid binding accepted")
			}
		})
	}
}
