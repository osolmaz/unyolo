package appmanifest

import "testing"

func TestProfilesAndMinimumManifest(t *testing.T) {
	names, err := ProfileNames()
	if err != nil || len(names) != 5 || names[0] != "administration" || names[4] != "security" {
		t.Fatalf("names=%v err=%v", names, err)
	}
	manifest, err := Minimum([]string{"repo.metadata.read", "pull_request.create"})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.APIVersion != "2026-03-10" || len(manifest.Permissions) == 0 {
		t.Fatalf("manifest=%+v", manifest)
	}
	if _, err := Minimum([]string{"http.request"}); err == nil {
		t.Fatal("unknown operation accepted")
	}
}

func TestProfilesFailClosedOnMalformedMetadata(t *testing.T) {
	original := raw
	t.Cleanup(func() { raw = original })
	for _, invalid := range [][]byte{
		[]byte(`not-json`),
		[]byte(`{"version":2,"api_version":"2026-03-10","profiles":{"a":{},"b":{},"c":{},"d":{},"e":{}}}`),
		[]byte(`{"version":1,"api_version":"latest","profiles":{"a":{},"b":{},"c":{},"d":{},"e":{}}}`),
	} {
		raw = invalid
		if _, err := LoadProfiles(); err == nil {
			t.Fatalf("invalid profiles accepted: %s", invalid)
		}
	}
}
