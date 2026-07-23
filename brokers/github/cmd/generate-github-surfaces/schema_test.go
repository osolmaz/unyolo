package main

import (
	"slices"
	"testing"
)

func TestIssueResponseProjectionKeepsPullRequestDiscriminator(t *testing.T) {
	t.Parallel()
	schema := map[string]any{
		"type": "array",
		"items": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"number": map[string]any{"type": "integer"},
				"pull_request": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"url":   map[string]any{"type": "string"},
						"token": map[string]any{"type": "string"},
					},
				},
			},
		},
	}

	projection := responseProjection("issue.issues_list_for_repo", schema)
	if !slices.Contains(projection, "pull_request.url") {
		t.Fatalf("response projection = %v, want pull_request.url", projection)
	}
	if slices.Contains(projection, "pull_request.token") {
		t.Fatalf("response projection exposes unsafe field: %v", projection)
	}
}
