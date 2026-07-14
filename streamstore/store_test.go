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

func TestOwnedStreamRemainsAvailableUntilDeliveryIsAcknowledged(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reference, err := store.Put("bob", "archive.download", "request-1", "application/zip", strings.NewReader("archive"), 32, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	file, opened, err := store.OpenOwned("bob", reference.ID)
	if err != nil || opened != reference {
		t.Fatalf("open = %+v, %v", opened, err)
	}
	buffer := make([]byte, 1)
	_, _ = file.Read(buffer)
	_ = file.Close()
	if store.Validate(reference) != nil {
		t.Fatal("interrupted delivery consumed the stream")
	}
	file, _, err = store.OpenOwned("bob", reference.ID)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(file)
	_ = file.Close()
	if string(data) != "archive" || store.Delete(reference) != nil {
		t.Fatalf("retry data = %q", data)
	}
	if _, _, err := store.OpenOwned("bob", reference.ID); err == nil {
		t.Fatal("acknowledged stream remained available")
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

func TestStoreIdempotentlyReusesMatchingUpload(t *testing.T) {
	store, _ := Open(t.TempDir())
	expires := time.Now().Add(time.Hour)
	first, err := store.Put("bob", "release.upload", "request-1", "application/octet-stream", strings.NewReader("canary"), 32, expires)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := store.Put("bob", "release.upload", "request-1", "application/octet-stream", strings.NewReader("canary"), 32, expires.Add(time.Minute))
	if err != nil || replayed != first {
		t.Fatalf("replayed = %+v, %v; want %+v", replayed, err, first)
	}
	if _, err := store.Put("bob", "release.upload", "request-1", "application/octet-stream", strings.NewReader("different"), 32, expires); err == nil {
		t.Fatal("idempotency key accepted different bytes")
	}
	if _, err := store.Put("bob", "release.upload", "request-1", "text/plain", strings.NewReader("canary"), 32, expires); err == nil {
		t.Fatal("idempotency key accepted different media type")
	}
}

func TestStoreRetainsReplayIdentityWithoutStreamBytes(t *testing.T) {
	store, _ := Open(t.TempDir())
	store.now = func() time.Time { return time.Unix(100, 0) }
	first, err := store.Put("bob", "release.upload", "request-1", "application/octet-stream", strings.NewReader("canary"), 32, time.Unix(110, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Retire(first, time.Unix(200, 0)); err != nil {
		t.Fatal(err)
	}
	if err := store.Retire(first, time.Unix(210, 0)); err != nil {
		t.Fatalf("repeated retirement = %v", err)
	}
	conflict := first
	conflict.Digest = strings.Repeat("0", len(first.Digest))
	if err := store.Retire(conflict, time.Unix(210, 0)); err == nil {
		t.Fatal("conflicting retirement was accepted")
	}
	if store.Validate(first) == nil {
		t.Fatal("retired stream bytes remain available")
	}
	store.now = func() time.Time { return time.Unix(150, 0) }
	if _, err := store.Put("bob", "release.upload", "request-2", "application/octet-stream", strings.NewReader("other"), 32, time.Unix(160, 0)); err != nil {
		t.Fatal(err)
	}
	replayed, err := store.Put("bob", "release.upload", "request-1", "application/octet-stream", strings.NewReader("canary"), 32, time.Unix(160, 0))
	if err != nil || replayed != first {
		t.Fatalf("retired replay = %+v, %v; want %+v", replayed, err, first)
	}
	if _, err := store.Put("bob", "release.upload", "request-1", "application/octet-stream", strings.NewReader("different"), 32, time.Unix(160, 0)); err == nil {
		t.Fatal("retired request key accepted different bytes")
	}
	store.now = func() time.Time { return time.Unix(201, 0) }
	replacement, err := store.Put("bob", "release.upload", "request-1", "application/octet-stream", strings.NewReader("canary"), 32, time.Unix(220, 0))
	if err != nil || replacement.ID == first.ID {
		t.Fatalf("expired replay marker replacement = %+v, %v", replacement, err)
	}
}

func TestStoreDeleteRemovesAllStreamState(t *testing.T) {
	store, _ := Open(t.TempDir())
	reference, err := store.Put("bob", "release.upload", "request-1", "application/octet-stream", strings.NewReader("canary"), 32, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(reference); err != nil || store.Validate(reference) == nil {
		t.Fatalf("delete = %v", err)
	}
	if err := store.Delete(reference); err != nil {
		t.Fatalf("repeated delete = %v", err)
	}
	if err := store.Delete(Reference{ID: "invalid"}); err == nil {
		t.Fatal("invalid delete was accepted")
	}
}

func TestStoreRejectsInvalidReplayMetadata(t *testing.T) {
	store, _ := Open(t.TempDir())
	if _, err := store.loadReplayLocked("invalid"); err == nil {
		t.Fatal("invalid replay id was accepted")
	}
	id := "stream_abcdefghijklmnopqrstuvwx"
	if err := os.WriteFile(store.replayPath(id), []byte(`{"reference":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.loadReplayLocked(id); err == nil {
		t.Fatal("corrupt replay metadata was accepted")
	}
}

func TestStoreEnforcesAggregateQuotaAfterSweeping(t *testing.T) {
	store, _ := Open(t.TempDir())
	store.maxFiles = 2
	store.maxBytes = 8
	store.now = func() time.Time { return time.Unix(100, 0) }
	if _, err := store.Put("bob", "release.upload", "request-1", "application/octet-stream", strings.NewReader("1234"), 4, time.Unix(101, 0)); err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return time.Unix(102, 0) }
	if _, err := store.Put("bob", "release.upload", "request-2", "application/octet-stream", strings.NewReader("12345"), 5, time.Unix(200, 0)); err != nil {
		t.Fatalf("expired upload was not swept before quota check: %v", err)
	}
	if _, err := store.Put("bob", "release.upload", "request-3", "application/octet-stream", strings.NewReader("1234"), 4, time.Unix(200, 0)); err == nil {
		t.Fatal("aggregate byte quota was not enforced")
	}
	if _, err := store.Put("bob", "release.upload", "request-4", "application/octet-stream", strings.NewReader("1"), 1, time.Unix(200, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("bob", "release.upload", "request-5", "application/octet-stream", strings.NewReader("1"), 1, time.Unix(200, 0)); err == nil {
		t.Fatal("aggregate file quota was not enforced")
	}
}
