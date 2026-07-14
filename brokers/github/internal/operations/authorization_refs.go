package operations

import (
	"slices"
	"strings"
)

func normalizeOperationAuthorizationAttrs(operation string, attrs map[string][]string) map[string][]string {
	if attrs == nil || !strings.HasPrefix(operation, "pull_request.") {
		return attrs
	}
	for _, name := range []string{"base_ref", "head_ref"} {
		for index, value := range attrs[name] {
			attrs[name][index] = canonicalPullRequestRef(value)
		}
	}
	if operation == "pull_request.create" && len(attrs["head_ref"]) > 0 {
		attrs["ref"] = slices.Clone(attrs["head_ref"])
	}
	return attrs
}

func canonicalPullRequestRef(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "refs/") {
		return value
	}
	if owner, branch, found := strings.Cut(value, ":"); found {
		return owner + ":refs/heads/" + branch
	}
	return "refs/heads/" + value
}
