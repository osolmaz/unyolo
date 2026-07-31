package component

import (
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/deployment/api"
	"github.com/osolmaz/unyolo/internal/config/secretfile"
)

func TestApplyAuthoritativeNamedSecretStore(t *testing.T) {
	t.Parallel()
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroupId(current.Gid)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "clients")
	store := SecretStore{
		ID: "clients", Destination: path, Mode: 0o600, Owner: current.Username, Group: group.Name,
		Entries: []SecretEntry{{Identity: "alice", Slot: "alice-secret"}, {Identity: "bob", Slot: "bob-secret"}},
	}
	actions := []api.CredentialAction{{Slot: "alice-secret", Action: "install"}, {Slot: "bob-secret", Action: "install"}}
	installed, err := applySecretStores([]SecretStore{store}, actions, map[string][]byte{
		"alice-secret": []byte(strings.Repeat("a", 32)), "bob-secret": []byte(strings.Repeat("b", 32)),
	}, map[string]bool{"secret-store-clients": true})
	if err != nil {
		t.Fatal(err)
	}
	defer clearSecrets(installed)
	values, err := secretfile.Parse(path)
	if err != nil || len(values) != 2 || values["alice"] != strings.Repeat("a", 32) || values["bob"] != strings.Repeat("b", 32) {
		t.Fatalf("named store = %#v, %v", values, err)
	}

	store.Entries = []SecretEntry{{Identity: "alice", Slot: "alice-secret", Rotate: true}}
	actions = []api.CredentialAction{{Slot: "alice-secret", Action: "rotate"}}
	if _, err := applySecretStores([]SecretStore{store}, actions, map[string][]byte{"alice-secret": []byte(strings.Repeat("c", 32))}, map[string]bool{"secret-store-clients": true}); err != nil {
		t.Fatal(err)
	}
	values, err = secretfile.Parse(path)
	if err != nil || len(values) != 1 || values["alice"] != strings.Repeat("c", 32) {
		t.Fatalf("rotated store = %#v, %v", values, err)
	}
}
