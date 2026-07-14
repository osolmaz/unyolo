package mcpcatalog

import (
	"testing"

	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
)

func allEnabled() Enabled {
	values := map[string]bool{}
	for _, descriptor := range opcatalog.MustAll() {
		values[descriptor.Name] = true
	}
	return Enabled{Client: values, Policy: values, Runtime: values}
}

func TestMCPExposureProfilesAreFilteredAndTyped(t *testing.T) {
	enabled := allEnabled()
	if tools, err := Tools(Exposure{}, enabled); err != nil || len(tools) != 0 {
		t.Fatalf("empty tools=%d err=%v", len(tools), err)
	}
	tools, err := Tools(DefaultExposure(), enabled)
	if err != nil || len(tools) != 4 {
		t.Fatalf("default tools=%d err=%v", len(tools), err)
	}
	for _, tool := range tools {
		schema := tool["inputSchema"].(map[string]any)
		if schema["additionalProperties"] != false {
			t.Fatalf("tool schema is open: %#v", tool)
		}
		properties := schema["properties"].(map[string]any)
		if properties["arguments"] == nil || properties["attrs"] != nil || properties["minutes"] != nil || properties["max_uses"] != nil {
			t.Fatalf("GitHub operation tool uses grant-request fields: %#v", tool)
		}
	}
	family, err := Selected(Exposure{Families: []string{"repo.*"}}, enabled)
	if err != nil || len(family) == 0 {
		t.Fatalf("family=%d err=%v", len(family), err)
	}
	for _, descriptor := range family {
		if descriptor.ExplicitOnly {
			t.Fatalf("family exposed explicit operation %q", descriptor.Name)
		}
	}
}

func TestMCPExactAdministrativeAndCompleteProfiles(t *testing.T) {
	enabled := allEnabled()
	selected, err := Selected(Exposure{Exact: []string{"repo.visibility.update"}}, enabled)
	if err != nil || len(selected) != 1 || selected[0].Name != "repo.visibility.update" {
		t.Fatalf("selected=%v err=%v", selected, err)
	}
	complete, err := Selected(Exposure{Complete: true}, enabled)
	if err != nil {
		t.Fatal(err)
	}
	agent := 0
	for _, descriptor := range opcatalog.MustAll() {
		if descriptor.AgentFacing {
			agent++
		}
	}
	if len(complete) != agent {
		t.Fatalf("complete=%d agent=%d", len(complete), agent)
	}
	tools, err := Tools(Exposure{Complete: true}, enabled)
	if err != nil || len(tools) != agent {
		t.Fatalf("complete typed tools=%d agent=%d err=%v", len(tools), agent, err)
	}
}

func TestMCPRequiresClientPolicyAndRuntimeEnablement(t *testing.T) {
	enabled := allEnabled()
	delete(enabled.Policy, "repo.metadata.read")
	selected, err := Selected(DefaultExposure(), enabled)
	if err != nil {
		t.Fatal(err)
	}
	for _, descriptor := range selected {
		if descriptor.Name == "repo.metadata.read" {
			t.Fatal("policy-disabled operation advertised")
		}
	}
	delete(enabled.Client, "repo.contents.read")
	delete(enabled.Runtime, "pull_request.create")
	selected, err = Selected(DefaultExposure(), enabled)
	if err != nil || len(selected) != 1 || selected[0].Name != "pull_request.update" {
		t.Fatalf("selected=%v err=%v", selected, err)
	}
}

func TestPagedDiscoveryReturnsExhaustiveCatalog(t *testing.T) {
	cursor, count := "", 0
	for {
		page, err := Discover(cursor, 73)
		if err != nil {
			t.Fatal(err)
		}
		count += len(page.Items)
		if page.NextCursor == "" {
			if page.Total != opcatalog.ExpectedCount {
				t.Fatalf("total=%d", page.Total)
			}
			break
		}
		cursor = page.NextCursor
	}
	if count != opcatalog.ExpectedCount {
		t.Fatalf("discovered=%d", count)
	}
}
