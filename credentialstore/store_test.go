package credentialstore //nolint:testpackage // Tests exercise private integrity helpers.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	if store.Exists("missing") || store.Exists("../escape") {
		t.Fatal("invalid or missing slot exists")
	}
	if err := store.Delete("../escape"); err == nil {
		t.Fatal("Delete accepted invalid slot")
	}
}

func TestStoreExistsAndDelete(t *testing.T) {
	t.Parallel()
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("github-user-42", "github-app-user-token", []byte("encrypted")); err != nil {
		t.Fatal(err)
	}
	if !store.Exists("github-user-42") {
		t.Fatal("stored slot does not exist")
	}
	if err := store.Delete("github-user-42"); err != nil {
		t.Fatal(err)
	}
	if store.Exists("github-user-42") {
		t.Fatal("deleted slot still exists")
	}
	if err := store.Delete("github-user-42"); err != nil {
		t.Fatalf("idempotent Delete() error = %v", err)
	}
	var nilStore *Store
	if nilStore.Exists("github-user-42") {
		t.Fatal("nil store reported a slot")
	}
	if err := nilStore.Delete("github-user-42"); err == nil {
		t.Fatal("nil store deleted a slot")
	}
}

func TestStoreNamespacesIsolateIdenticalSlots(t *testing.T) {
	t.Parallel()
	state := t.TempDir()
	users, err := OpenNamespace(state, "github-users")
	if err != nil {
		t.Fatal(err)
	}
	outputs, err := OpenNamespace(state, "github-outputs")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := users.Put("github-user-7", "github-app-user-token", []byte("user-secret")); err != nil {
		t.Fatal(err)
	}
	if _, err := outputs.Put("github-user-7", "github-output-token", []byte("output-secret")); err != nil {
		t.Fatal(err)
	}
	userValue, _, userErr := users.Get("github-user-7", "github-app-user-token")
	outputValue, _, outputErr := outputs.Get("github-user-7", "github-output-token")
	if userErr != nil || outputErr != nil || string(userValue) != "user-secret" || string(outputValue) != "output-secret" {
		t.Fatalf("namespaced values = %q, %q; errors = %v, %v", userValue, outputValue, userErr, outputErr)
	}
	userPath, _ := NamespacePath(state, "github-users")
	outputPath, _ := NamespacePath(state, "github-outputs")
	if userPath == outputPath || !strings.HasPrefix(userPath, state+string(filepath.Separator)) || !strings.HasPrefix(outputPath, state+string(filepath.Separator)) {
		t.Fatalf("namespace paths = %q, %q", userPath, outputPath)
	}
}

func TestStoreRejectsUnsafeNamespaces(t *testing.T) {
	t.Parallel()
	state := t.TempDir()
	for _, namespace := range []string{"", "../escape", "GitHub", "contains/slash"} {
		if _, err := OpenNamespace(state, namespace); err == nil {
			t.Fatalf("OpenNamespace accepted %q", namespace)
		}
	}
	if _, err := NamespacePath("", "github-users"); err == nil {
		t.Fatal("NamespacePath accepted an empty state directory")
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
	if _, _, err := nilStore.Get("slot", "token"); err == nil {
		t.Fatal("nil store returned a value")
	}
	if _, _, err := store.Get("../escape", "token"); err == nil {
		t.Fatal("invalid slot was read")
	}
}

func TestStoreRejectsMalformedEncryptedRecords(t *testing.T) {
	t.Parallel()
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeRecord := func(t *testing.T, record []byte) {
		t.Helper()
		if err := os.WriteFile(store.path("slot"), record, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.Get("slot", "token"); err == nil {
			t.Fatal("Get() accepted malformed record")
		}
	}
	writeRecord(t, []byte(`not-json`))
	writeRecord(t, []byte(`{"slot":"other","kind":"token","size":1}`))
	writeRecord(t, []byte(`{"slot":"slot","kind":"token","size":0}`))
	writeRecord(t, []byte(`{"slot":"slot","kind":"token","size":1,"nonce":"!","ciphertext":"!"}`))
	writeRecord(t, []byte(`{"slot":"slot","kind":"token","size":1,"nonce":"AA","ciphertext":"AA"}`))

	metadata := Metadata{Slot: "slot", Kind: "token", Digest: strings.Repeat("0", 64), Size: 6, UpdatedAt: time.Now().UTC()}
	nonce := make([]byte, store.aead.NonceSize())
	ciphertext := store.aead.Seal(nil, nonce, []byte("secret"), associatedData(metadata))
	record, err := json.Marshal(encryptedRecord{Metadata: metadata,
		Nonce: base64.RawStdEncoding.EncodeToString(nonce), Ciphertext: base64.RawStdEncoding.EncodeToString(ciphertext)})
	if err != nil {
		t.Fatal(err)
	}
	writeRecord(t, record)

	oversized := make([]byte, 2*maxCredentialBytes+1)
	writeRecord(t, oversized)
}

func TestCredentialStoreFilesystemFailures(t *testing.T) {
	t.Parallel()
	if _, err := Open(""); err == nil {
		t.Fatal("Open accepted empty state directory")
	}
	state := t.TempDir()
	if err := os.WriteFile(filepath.Join(state, "credential-slots.key"), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(state); err == nil {
		t.Fatal("Open accepted a short key")
	}
	if err := atomicWrite(filepath.Join(state, "missing", "slot.json"), []byte("value")); err == nil {
		t.Fatal("atomicWrite accepted a missing directory")
	}
	value := []byte("secret")
	zero(value)
	if !bytes.Equal(value, make([]byte, len(value))) {
		t.Fatalf("zero() = %v", value)
	}
}
