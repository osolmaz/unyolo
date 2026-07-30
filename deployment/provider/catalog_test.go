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
