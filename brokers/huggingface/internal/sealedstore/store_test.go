package sealedstore

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStoreEncryptsBindsAndConsumesOnce(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("canary-super-secret-value")
	reference, err := store.Put("bob", "space.secret.set", secret, time.Now().Add(time.Hour))
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
	reference, _ := store.Put("bob", "space.secret.set", []byte("one-use"), time.Now().Add(time.Hour))
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

func TestStoreIdempotentlyBindsOneRequestKey(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	first, err := store.PutForRequest("bob", "space.secret.set", "submission-1", []byte("secret"), expires)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := store.PutForRequest("bob", "space.secret.set", "submission-1", []byte("secret"), expires.Add(time.Minute))
	if err != nil || replayed != first {
		t.Fatalf("idempotent PutForRequest() = %+v, %v; want %+v", replayed, err, first)
	}
	if _, err := store.PutForRequest("bob", "space.secret.set", "submission-1", []byte("different"), expires); err == nil {
		t.Fatal("request key accepted different sealed content")
	}
}

func TestStorePreservesIdempotencyAfterConsumeAndDelete(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	for _, requestKey := range []string{"consumed", "deleted"} {
		first, err := store.PutForRequest("bob", "space.secret.set", requestKey, []byte("secret"), expires)
		if err != nil {
			t.Fatal(err)
		}
		if requestKey == "consumed" {
			value, consumeErr := store.Consume(first)
			if consumeErr != nil || string(value) != "secret" {
				t.Fatalf("Consume() = %q, %v", value, consumeErr)
			}
		} else if err := store.Delete(first); err != nil {
			t.Fatal(err)
		}
		reopened, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		replayed, err := reopened.PutForRequest("bob", "space.secret.set", requestKey, []byte("secret"), expires)
		if err != nil || replayed != first {
			t.Fatalf("replayed %s reference = %+v, %v; want %+v", requestKey, replayed, err, first)
		}
		if _, err := reopened.Get(first); err == nil {
			t.Fatalf("%s payload remained readable", requestKey)
		}
		if _, err := reopened.PutForRequest("bob", "space.secret.set", requestKey, []byte("different"), expires); err == nil {
			t.Fatalf("%s request key accepted different plaintext", requestKey)
		}
		store = reopened
	}
}

func TestStoreSweepsExpiredAndIncompletePayloads(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := store.PutForRequest("bob", "space.secret.set", "expiring", []byte("secret"), time.Now().Add(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	removed, err := store.SweepExpired(time.Now())
	if err != nil || removed != 1 {
		t.Fatalf("SweepExpired() = %d, %v", removed, err)
	}
	if _, err := store.Get(reference); err == nil {
		t.Fatal("expired sealed payload remained readable")
	}
	active, err := store.PutForRequest("bob", "space.secret.set", "consuming", []byte("secret"), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "sealed-payloads", active.ID+".bin")
	if err := os.Rename(source, source+".consuming"); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(source + ".consuming"); !os.IsNotExist(err) {
		t.Fatalf("unsupported consume artifact remains: %v", err)
	}
}

func TestStoreRetainsConsumedMarkerForIdempotencyWindow(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reference, err := store.PutForRequest("bob", "space.secret.set", "retained", []byte("secret"), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Consume(reference); err != nil {
		t.Fatal(err)
	}
	afterExpiry := time.Unix(reference.ExpiresAt, 0).Add(time.Second)
	if removed, err := store.SweepExpired(afterExpiry); err != nil || removed != 0 {
		t.Fatalf("early SweepExpired() = %d, %v", removed, err)
	}
	store.mu.Lock()
	replayed, found, err := store.findRequestLocked(reference.Owner, reference.Purpose, reference.RequestKey, reference.Digest, reference.Size)
	store.mu.Unlock()
	if err != nil || !found || replayed != reference {
		t.Fatalf("retained request = %+v, %v, %v", replayed, found, err)
	}
	afterRetention := time.Unix(reference.ExpiresAt, 0).Add(consumedMarkerRetention + time.Second)
	if removed, err := store.SweepExpired(afterRetention); err != nil || removed != 1 {
		t.Fatalf("final SweepExpired() = %d, %v", removed, err)
	}
}

func TestStorePersistsKeyAndRejectsUnsafePermissions(t *testing.T) {
	dir := t.TempDir()
	first, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	reference, _ := first.Put("bob", "space.secret.set", []byte("survives restart"), time.Now().Add(time.Hour))
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
	reference, _ := store.Put("bob", "space.secret.set", []byte("secret"), time.Now().Add(time.Hour))
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

func TestStoreBindsOwnerPurposeAndExpiry(t *testing.T) {
	store, _ := Open(t.TempDir())
	reference, _ := store.Put("bob", "space.secret.set", []byte("secret"), time.Now().Add(time.Hour))
	wrongOwner := reference
	wrongOwner.Owner = "alice"
	if _, err := store.Get(wrongOwner); err == nil {
		t.Fatal("owner substitution accepted")
	}
	wrongPurpose := reference
	wrongPurpose.Purpose = "webhook.create"
	if _, err := store.Get(wrongPurpose); err == nil {
		t.Fatal("purpose substitution accepted")
	}
	expired, _ := store.Put("bob", "space.secret.set", []byte("old"), time.Now().Add(time.Millisecond))
	time.Sleep(2 * time.Millisecond)
	if _, err := store.Get(expired); err == nil {
		t.Fatal("expired payload accepted")
	}
}

func TestStoreDeleteAndInputValidation(t *testing.T) {
	store, _ := Open(t.TempDir())
	for _, test := range []struct {
		owner, purpose string
		value          []byte
		expires        time.Time
	}{
		{"../bob", "space.secret.set", []byte("secret"), time.Now().Add(time.Hour)},
		{"bob", "invalid", []byte("secret"), time.Now().Add(time.Hour)},
		{"bob", "space.secret.set", nil, time.Now().Add(time.Hour)},
		{"bob", "space.secret.set", make([]byte, maxSecretBytes+1), time.Now().Add(time.Hour)},
		{"bob", "space.secret.set", []byte("secret"), time.Now().Add(-time.Hour)},
		{"bob", "space.secret.set", []byte("secret"), time.Now().Add(25 * time.Hour)},
	} {
		if _, err := store.Put(test.owner, test.purpose, test.value, test.expires); err == nil {
			t.Fatalf("invalid payload accepted: %+v", test)
		}
	}
	reference, _ := store.Put("bob", "space.secret.set", []byte("secret"), time.Now().Add(time.Hour))
	if err := store.Delete(reference); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(reference); err != nil {
		t.Fatal("idempotent delete failed:", err)
	}
	bad := reference
	bad.Digest = "not-hex"
	if err := store.Delete(bad); err == nil {
		t.Fatal("invalid reference deletion accepted")
	}
	if _, err := store.Consume(bad); err == nil {
		t.Fatal("invalid reference consumption accepted")
	}
	if _, err := store.Consume(reference); err == nil {
		t.Fatal("missing payload was consumed")
	}
	var nilStore *Store
	if _, err := nilStore.Put("bob", "space.secret.set", []byte("secret"), time.Now().Add(time.Hour)); err == nil {
		t.Fatal("nil store accepted payload")
	}
}

func TestStoreRejectsUnsupportedFormatAndBindingDrift(t *testing.T) {
	dir := t.TempDir()
	store, _ := Open(dir)
	reference, _ := store.Put("bob", "space.secret.set", []byte("secret"), time.Now().Add(time.Hour))
	path := filepath.Join(dir, "sealed-payloads", reference.ID+".bin")
	data, _ := os.ReadFile(path)
	data[0] = 99
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(reference); err == nil {
		t.Fatal("unsupported sealed format accepted")
	}
	reference, _ = store.Put("bob", "space.secret.set", []byte("secret"), time.Now().Add(time.Hour))
	reference.Size++
	if _, err := store.Get(reference); err == nil {
		t.Fatal("sealed payload size drift accepted")
	}
}

func TestSealedStoreFilesystemAndKeyFailures(t *testing.T) {
	t.Parallel()
	if _, err := Open(""); err == nil {
		t.Fatal("Open accepted empty state directory")
	}
	state := t.TempDir()
	if err := os.WriteFile(filepath.Join(state, "sealed-payload.key"), []byte("not-base64"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(state); err == nil {
		t.Fatal("Open accepted invalid key")
	}
}

func TestReferenceValidationVariants(t *testing.T) {
	t.Parallel()
	reference, err := randomReference()
	if err != nil || !referencePattern.MatchString(reference) {
		t.Fatalf("randomReference() = %q, %v", reference, err)
	}
	valid := Reference{ID: reference, Owner: "bob", Purpose: "space.secret.set", RequestKey: "request-1", Digest: strings.Repeat("a", 64), Size: 1, ExpiresAt: time.Now().Add(time.Hour).Unix()}
	for _, mutate := range []func(*Reference){
		func(value *Reference) { value.ID = "bad" },
		func(value *Reference) { value.Owner = "../bob" },
		func(value *Reference) { value.Purpose = "bad" },
		func(value *Reference) { value.RequestKey = "" },
		func(value *Reference) { value.Digest = "short" },
		func(value *Reference) { value.Digest = strings.Repeat("z", 64) },
		func(value *Reference) { value.Size = 0 },
		func(value *Reference) { value.Size = maxSecretBytes + 1 },
		func(value *Reference) { value.ExpiresAt = 0 },
	} {
		candidate := valid
		mutate(&candidate)
		if err := validateReference(candidate); err == nil {
			t.Fatalf("validateReference(%+v) succeeded", candidate)
		}
	}
	if err := validateReference(valid); err != nil {
		t.Fatalf("validateReference(valid) = %v", err)
	}
}
