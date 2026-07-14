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
		{"url", func(value *Binding) { value.PathTemplate = "https://example.invalid" }},
		{"missing response projection", func(value *Binding) { value.ResponseProjection = nil }},
		{"unsafe response projection", func(value *Binding) { value.ResponseProjection = []string{"token"} }},
		{"parameter location", func(value *Binding) { value.ArgumentParameters = []Parameter{{Name: "page", In: "header"}} }},
		{"raw parameter", func(value *Binding) { value.ArgumentParameters = []Parameter{{Name: "method", In: "query"}} }},
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
