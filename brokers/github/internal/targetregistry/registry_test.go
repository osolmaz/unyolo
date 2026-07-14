package targetregistry

import (
	"sync"
	"testing"
)

func TestRegistryIsClosedAndComplete(t *testing.T) {
	values, err := All()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"repo", "organization", "enterprise", "pull_request", "workflow", "advisory", "installation"} {
		if !Known(kind) {
			t.Fatalf("target kind %q missing", kind)
		}
	}
	if Known("url") || len(values) < 30 {
		t.Fatalf("target registry = %d entries", len(values))
	}
}

func TestRepositoryIdentity(t *testing.T) {
	owner, repo, ok := RepositoryIdentity(map[string]any{"owner": " acme ", "name": " project "})
	if !ok || owner != "acme" || repo != "project" {
		t.Fatalf("RepositoryIdentity() = %q, %q, %t", owner, repo, ok)
	}
	if _, _, ok := RepositoryIdentity(map[string]any{"owner": "acme"}); ok {
		t.Fatal("incomplete repository identity accepted")
	}
	owner, repo, ok = RepositoryIdentity(map[string]any{"owner": "acme", "repo": "project", "name": "production"})
	if !ok || owner != "acme" || repo != "project" {
		t.Fatalf("nested RepositoryIdentity() = %q, %q, %t", owner, repo, ok)
	}
}

func TestRegistryLoadFailsClosed(t *testing.T) {
	original := append([]byte(nil), raw...)
	t.Cleanup(func() {
		raw = original
		once = sync.Once{}
		values, loadErr = nil, nil
		_, _ = All()
	})
	for name, invalid := range map[string][]byte{
		"json":   []byte(`not-json`),
		"schema": []byte(`[{"kind":"repo","schema":"target.repo.v2","policy_fields":["owner"]}]`),
		"fields": []byte(`[{"kind":"repo","schema":"target.repo.v1","policy_fields":[]}]`),
		"order":  []byte(`[{"kind":"repo","schema":"target.repo.v1","policy_fields":["owner"]},{"kind":"repo","schema":"target.repo.v1","policy_fields":["owner"]}]`),
		"unsafe": []byte(`[{"kind":"repo","schema":"target.repo.v1","policy_fields":["url"]}]`),
	} {
		t.Run(name, func(t *testing.T) {
			raw = invalid
			once = sync.Once{}
			values, loadErr = nil, nil
			if _, err := All(); err == nil || Known("repo") {
				t.Fatal("invalid target registry accepted")
			}
		})
	}
}
