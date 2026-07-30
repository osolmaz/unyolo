package provider

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDirectorySortsDefaultsAndRejectsUnknownFields(t *testing.T) {
	root := t.TempDir()
	writeOption(t, root, "one.json", `{"api_version":"unyolo.io/setup-provider/v1","id":"one","label":"One","selected":false}`)
	writeOption(t, root, "two.json", `{"api_version":"unyolo.io/setup-provider/v1","id":"two","label":"Two","selected":true}`)
	options, err := LoadDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(options) != 2 || options[0].ID != "two" || !options[0].Selected || options[1].ID != "one" {
		t.Fatalf("options = %+v", options)
	}
	writeOption(t, root, "bad.json", `{"api_version":"unyolo.io/setup-provider/v1","id":"bad","label":"Bad","selected":false,"extra":true}`)
	if _, err := LoadDirectory(root); err == nil {
		t.Fatal("catalog accepted an unknown field")
	}
}

func TestLoadDirectoryRejectsSymlinkEntry(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "github.json")
	writeOption(t, filepath.Dir(outside), filepath.Base(outside), `{"api_version":"unyolo.io/setup-provider/v1","id":"github","label":"GitHub","selected":true}`)
	if err := os.Symlink(outside, filepath.Join(root, "github.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDirectory(root); err == nil {
		t.Fatal("catalog accepted a symlink entry")
	}
}

func TestSelectionKeyIsStableAndBoundToCatalog(t *testing.T) {
	options := []Option{
		{APIVersion: APIVersion, ID: "github", Label: "GitHub", Selected: true},
		{APIVersion: APIVersion, ID: "huggingface", Label: "Hugging Face", Selected: true},
	}
	key, err := SelectionKey(options, []string{"huggingface", "github"})
	if err != nil || key != "github+huggingface" {
		t.Fatalf("SelectionKey() = %q, %v", key, err)
	}
	for _, selected := range [][]string{nil, {"github", "github"}, {"sudo"}} {
		if _, err := SelectionKey(options, selected); err == nil {
			t.Fatalf("SelectionKey accepted %v", selected)
		}
	}
}

func TestRepositoryProviderCatalog(t *testing.T) {
	root := t.TempDir()
	for _, provider := range []string{"github", "huggingface", "sudo"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "brokers", provider, "deployment", "provider.json"))
		if err != nil {
			t.Fatal(err)
		}
		writeOption(t, root, provider+".json", string(data))
	}
	options, err := LoadDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(options) != 3 || options[0].ID != "github" || options[1].ID != "huggingface" || options[2].ID != "sudo" {
		t.Fatalf("options = %+v", options)
	}
}

func writeOption(t *testing.T, root, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
