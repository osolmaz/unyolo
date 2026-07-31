package setup

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/deployment/flow"
)

// TestBackSentinelAppearsWhenNavigationEnabled proves the terminal prompter
// exposes an inline "← Go back" option when Navigation.CanGoBack is true.
func TestBackSentinelAppearsWhenNavigationEnabled(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var output bytes.Buffer
	// The prompter appends "← Go back" as the last inline option. In
	// accessible mode the entries are indexed starting at 1, so choice 3
	// selects the sentinel and returns a navigation error.
	prompter := New(Options{Input: strings.NewReader("3\n"), Output: &output, Accessible: true, Width: 80})
	_, err := prompter.Select(context.Background(), flow.SelectPrompt{
		Message:    "Choose",
		Options:    []flow.Option{{Value: "one", Label: "One"}, {Value: "two", Label: "Two"}},
		Navigation: flow.Navigation{CanGoBack: true},
	})
	if err == nil {
		t.Fatal("Select accepted back sentinel without navigation error")
	}
	navigation, ok := err.(flow.NavigationError)
	if !ok || navigation.Direction != "back" {
		t.Fatalf("expected back navigation, got %v", err)
	}
	if !strings.Contains(output.String(), "Go back") {
		t.Fatalf("output missing back option: %q", output.String())
	}
}
