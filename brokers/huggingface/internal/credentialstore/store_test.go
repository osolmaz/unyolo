package credentialstore

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
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

func TestStorePersistsKeyAndRejectsTampering(t *testing.T) {
	state := t.TempDir()
	first, err := Open(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Put("deployment-token", "hf-token", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	second, err := Open(state)
	if err != nil {
		t.Fatal(err)
	}
	if value, _, err := second.Get("deployment-token", "hf-token"); err != nil || string(value) != "secret" {
		t.Fatalf("reopened Get() = %q, %v", value, err)
	}
	files, _ := filepath.Glob(filepath.Join(state, "credential-slots", "*.json"))
	record, _ := os.ReadFile(files[0])
	record[len(record)-2] ^= 1
	if err := os.WriteFile(files[0], record, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := second.Get("deployment-token", "hf-token"); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("tamper error = %v", err)
	}
	if err := os.Chmod(filepath.Join(state, "credential-slots.key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(state); err == nil {
		t.Fatal("unsafe key permissions accepted")
	}
}

func TestStoreRejectsInvalidValuesAndMetadata(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if ValidSlot("../escape") || !ValidSlot("deployment-token") {
		t.Fatal("slot validation mismatch")
	}
	if _, err := store.Put("slot", "token", nil); err == nil {
		t.Fatal("empty credential accepted")
	}
	if _, err := store.Put("slot", "token", make([]byte, maxCredentialBytes+1)); err == nil {
		t.Fatal("oversized credential accepted")
	}
	if _, err := store.Put("slot", "token", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Get("slot", "other"); err == nil {
		t.Fatal("wrong credential kind accepted")
	}
	var nilStore *Store
	if _, err := nilStore.Put("slot", "token", []byte("secret")); err == nil {
		t.Fatal("nil store accepted a value")
	}
}
