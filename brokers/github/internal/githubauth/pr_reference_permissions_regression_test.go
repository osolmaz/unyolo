package githubauth

import (
	"reflect"
	"testing"
)

// Creating a private-repository PR must read the existing head/base refs.
// App registration permissions do not survive exact per-operation narrowing.
func TestPullRequestCreateIncludesReadOnlyRefAccess(t *testing.T) {
	for _, tc := range []struct {
		operation string
		want      map[string]string
	}{
		{"pull_request.create", map[string]string{"contents": "read", "pull_requests": "write"}},
		{"pull_request.get", map[string]string{"contents": "read", "pull_requests": "read"}},
		{"git.fetch", map[string]string{"contents": "read"}},
	} {
		t.Run(tc.operation, func(t *testing.T) {
			got, err := permissionsForOperation(tc.operation)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("permissionsForOperation(%q) = %v, %v; want %v", tc.operation, got, err, tc.want)
			}
		})
	}
}
