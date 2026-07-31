package copy

import (
	"strings"
	"testing"
)

func TestScreensAreUniqueAndPopulated(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for id, screen := range Screens {
		if seen[id] {
			t.Fatalf("duplicate screen id %q", id)
		}
		seen[id] = true
		if strings.TrimSpace(screen.Question) == "" {
			t.Fatalf("screen %q has no question", id)
		}
	}
}

func TestScreensAvoidForbiddenNormalTerms(t *testing.T) {
	t.Parallel()
	corpus := strings.ToLower(Title + " " + Intro + " " + FooterHint)
	for _, screen := range Screens {
		corpus += " " + strings.ToLower(screen.Question) + " " + strings.ToLower(screen.Reason) + " " + strings.ToLower(screen.Primary) + " " + strings.ToLower(screen.Secondary)
	}
	for _, goal := range Goals {
		corpus += " " + strings.ToLower(goal.Label) + " " + strings.ToLower(goal.Hint)
	}
	for _, service := range Services {
		corpus += " " + strings.ToLower(service.Label) + " " + strings.ToLower(service.Hint)
	}
	for _, agent := range AgentLocations {
		corpus += " " + strings.ToLower(agent.Label) + " " + strings.ToLower(agent.Hint)
	}
	for _, forbidden := range ForbiddenNormalTerms {
		if strings.Contains(corpus, strings.ToLower(forbidden)) {
			t.Fatalf("normal copy contains forbidden term %q", forbidden)
		}
	}
}

func TestForbiddenTermsCoverContractVocabulary(t *testing.T) {
	t.Parallel()
	// GUIDED_INSTALLATION.md forbids these terms in the normal flow.
	required := []string{"deployment kit", "materialize", "runtime bundle", "plan digest", "protected worker"}
	set := map[string]bool{}
	for _, term := range ForbiddenNormalTerms {
		set[strings.ToLower(term)] = true
	}
	for _, term := range required {
		if !set[strings.ToLower(term)] {
			t.Fatalf("forbidden term list missing %q", term)
		}
	}
}
