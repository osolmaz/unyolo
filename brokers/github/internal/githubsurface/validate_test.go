package githubsurface

import "testing"

func TestGeneratedGitHubSurfaceValidates(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
}
