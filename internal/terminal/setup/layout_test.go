package setup

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/deployment/flow"
)

var hiddenCountPattern = regexp.MustCompile(`(\d+) more options below`)

func TestSelectionLayoutSizingAtSupportedWidths(t *testing.T) {
	t.Parallel()
	cases := []struct {
		width      int
		height     int
		count      int
		expectFull bool
	}{
		{width: 60, height: 24, count: 4, expectFull: true},
		{width: 60, height: 8, count: 12},
		{width: 80, height: 24, count: 3, expectFull: true},
		{width: 80, height: 12, count: 20},
		{width: 120, height: 24, count: 8, expectFull: true},
		{width: 120, height: 10, count: 32},
	}
	for _, test := range cases {
		test := test
		t.Run(fmt.Sprintf("%dx%d-%d", test.width, test.height, test.count), func(t *testing.T) {
			t.Parallel()
			prompter := &Prompter{width: test.width, height: test.height}
			description, height := prompter.selectionLayout("Choose one", flow.Navigation{}, test.count)
			if test.expectFull {
				if height != 0 || strings.Contains(description, "more options below") {
					t.Fatalf("expected full render, got height=%d description=%q", height, description)
				}
				return
			}
			if height <= 0 || height >= test.height {
				t.Fatalf("clipped viewport height = %d for terminal height=%d", height, test.height)
			}
			match := hiddenCountPattern.FindStringSubmatch(description)
			if len(match) != 2 {
				t.Fatalf("description missing hidden-count hint: %q", description)
			}
			hidden, err := strconv.Atoi(match[1])
			if err != nil || hidden <= 0 || hidden >= test.count {
				t.Fatalf("bad hidden count %q for count=%d: %v", match[1], test.count, err)
			}
		})
	}
}

func TestSelectionLayoutBackNavigationAppearsInDescription(t *testing.T) {
	t.Parallel()
	prompter := &Prompter{width: 80, height: 24}
	description, _ := prompter.selectionLayout("Choose", flow.Navigation{CanGoBack: true}, 3)
	if !strings.Contains(description, "back") {
		t.Fatalf("navigation hint missing: %q", description)
	}
}
