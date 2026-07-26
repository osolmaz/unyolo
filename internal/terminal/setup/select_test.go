package setup

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/deployment/flow"
)

func TestAccessibleSelect(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var output bytes.Buffer
	prompter := New(Options{Input: strings.NewReader("2\n"), Output: &output, Accessible: true, Width: 60})
	value, err := prompter.Select(context.Background(), flow.SelectPrompt{
		Message: "Mode", Searchable: true,
		Options: []flow.Option{{Value: "recommended", Label: "Recommended", Hint: "Safe defaults"}, {Value: "custom", Label: "Custom", Hint: "Review every setting"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if value != "custom" {
		t.Fatalf("value = %q, output = %q", value, output.String())
	}
	if !strings.Contains(output.String(), "Safe defaults") || !strings.Contains(output.String(), "Review every setting") {
		t.Fatalf("option hints missing: %q", output.String())
	}
}
