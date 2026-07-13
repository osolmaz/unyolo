package sealedstore

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestStoreEncryptsBindsAndConsumesOnce(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("canary-super-secret-value")
	reference, err := store.Put(secret)
	if err != nil || strings.Contains(reference.ID, string(secret)) {
		t.Fatalf("Put() = %+v, %v", reference, err)
	}
	ciphertext, err := os.ReadFile(filepath.Join(dir, "sealed-payloads", reference.ID+".bin"))
	if err != nil || bytes.Contains(ciphertext, secret) {
		t.Fatalf("ciphertext contains plaintext: %v", err)
	}
	got, err := store.Get(reference)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Get() = %q, %v", got, err)
	}
	consumed, err := store.Consume(reference)
	if err != nil || !bytes.Equal(consumed, secret) {
		t.Fatalf("Consume() = %q, %v", consumed, err)
	}
	if _, err := store.Get(reference); err == nil || strings.Contains(err.Error(), string(secret)) {
		t.Fatalf("second read error = %v", err)
	}
}

func TestStoreAllowsOnlyOneConcurrentConsumer(t *testing.T) {
	store, _ := Open(t.TempDir())
	reference, _ := store.Put([]byte("one-use"))
	var wait sync.WaitGroup
	results := make(chan bool, 12)
	for range 12 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			value, err := store.Consume(reference)
			results <- err == nil && string(value) == "one-use"
		}()
	}
	wait.Wait()
	close(results)
	succeeded := 0
	for result := range results {
		if result {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("successful consumers = %d", succeeded)
	}
}

func TestStorePersistsKeyAndRejectsUnsafePermissions(t *testing.T) {
	dir := t.TempDir()
	first, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	reference, _ := first.Put([]byte("survives restart"))
	second, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if value, err := second.Get(reference); err != nil || string(value) != "survives restart" {
		t.Fatalf("reopened Get() = %q, %v", value, err)
	}
	if err := os.Chmod(filepath.Join(dir, "sealed-payload.key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("unsafe key permissions accepted")
	}
}

func TestStoreRejectsTamperingAndBadReferences(t *testing.T) {
	dir := t.TempDir()
	store, _ := Open(dir)
	reference, _ := store.Put([]byte("secret"))
	path := filepath.Join(dir, "sealed-payloads", reference.ID+".bin")
	data, _ := os.ReadFile(path)
	data[len(data)-1] ^= 0xff
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(reference); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("tamper error = %v", err)
	}
	bad := reference
	bad.ID = "../../escape"
	if _, err := store.Get(bad); err == nil {
		t.Fatal("unsafe reference accepted")
	}
}
