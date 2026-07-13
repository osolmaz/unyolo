package credentialstore

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreEncryptsAndReplacesCredentialSlots(t *testing.T) {
	state := t.TempDir()
	store, err := Open(state)
	if err != nil {
		t.Fatal(err)
	}
	first := []byte("hf_first-secret")
	metadata, err := store.Put("deployment-token", "hf-service-account-token", first)
	if err != nil || metadata.Slot != "deployment-token" || metadata.Digest == "" {
		t.Fatalf("metadata=%#v err=%v", metadata, err)
	}
	files, _ := filepath.Glob(filepath.Join(state, "credential-slots", "*.json"))
	if len(files) != 1 {
		t.Fatalf("slot files = %v", files)
	}
	encoded, _ := os.ReadFile(files[0])
	if bytes.Contains(encoded, first) {
		t.Fatal("credential was stored in plaintext")
	}
	plaintext, loaded, err := store.Get("deployment-token", "hf-service-account-token")
	if err != nil || !bytes.Equal(plaintext, first) || loaded != metadata {
		t.Fatalf("plaintext=%q loaded=%#v err=%v", plaintext, loaded, err)
	}
	if _, err := store.Put("deployment-token", "hf-service-account-token", []byte("hf_second-secret")); err != nil {
		t.Fatal(err)
	}
	plaintext, _, err = store.Get("deployment-token", "hf-service-account-token")
	if err != nil || string(plaintext) != "hf_second-secret" {
		t.Fatalf("replacement=%q err=%v", plaintext, err)
	}
}

func TestStoreRejectsInvalidSlotsAndKinds(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ slot, kind string }{{"../escape", "token"}, {"slot", "Bad Kind"}, {"", "token"}} {
		if _, err := store.Put(test.slot, test.kind, []byte("secret")); err == nil {
			t.Fatalf("accepted slot=%q kind=%q", test.slot, test.kind)
		}
	}
	if _, _, err := store.Get("missing", "token"); err == nil {
		t.Fatal("missing slot was available")
	}
}
