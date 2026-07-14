package streamstore

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestStoreStreamsBoundedSingleUseFiles(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reference, err := store.Put("bob", "release.upload", "request-1", "application/octet-stream", strings.NewReader("canary"), 32, time.Now().Add(time.Hour))
	if err != nil || store.Validate(reference) != nil {
		t.Fatalf("reference = %+v err = %v", reference, err)
	}
	if _, _, err := store.Consume("alice", reference.ID); err == nil {
		t.Fatal("another owner consumed stream")
	}
	file, consumed, err := store.Consume("bob", reference.ID)
	if err != nil || consumed != reference {
		t.Fatalf("consume = %+v err = %v", consumed, err)
	}
	data, _ := io.ReadAll(file)
	_ = file.Close()
	if string(data) != "canary" {
		t.Fatalf("data = %q", data)
	}
	if _, _, err := store.Consume("bob", reference.ID); err == nil {
		t.Fatal("stream was reusable")
	}
}

func TestStoreRejectsOversizeAndSweepsExpiry(t *testing.T) {
	store, _ := Open(t.TempDir())
	if _, err := store.Put("bob", "release.upload", "request-1", "application/octet-stream", strings.NewReader("oversize"), 3, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("oversize stream accepted")
	}
	reference, err := store.Put("bob", "release.upload", "request-2", "application/octet-stream", strings.NewReader("canary"), 32, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	removed, err := store.SweepExpired(time.Now().Add(time.Minute))
	if err != nil || removed != 1 || store.Validate(reference) == nil {
		t.Fatalf("removed = %d err = %v", removed, err)
	}
}

func TestStoreRejectsContentTampering(t *testing.T) {
	store, _ := Open(t.TempDir())
	reference, err := store.Put("bob", "release.upload", "request-1", "application/octet-stream", strings.NewReader("canary"), 32, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.dataPath(reference.ID), []byte("change"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.OpenStream(reference); err == nil {
		t.Fatal("tampered stream opened")
	}
}
