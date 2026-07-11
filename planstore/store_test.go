package planstore

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreRoundTripAndCorruption(t *testing.T) {
	t.Parallel()
	store, err := New(filepath.Join(t.TempDir(), "plans"), "test")
	if err != nil {
		t.Fatal(err)
	}
	canonical := []byte(`{"schema":"test/v1","value":1}`)
	digest, err := store.Put(canonical)
	if err != nil || !ValidDigest(digest) {
		t.Fatalf("Put() = %q, %v", digest, err)
	}
	again, err := store.Put(canonical)
	if err != nil || again != digest {
		t.Fatalf("second Put() = %q, %v", again, err)
	}
	got, err := store.Get(digest)
	if err != nil || string(got) != string(canonical) {
		t.Fatalf("Get() = %q, %v", got, err)
	}
	if err := os.WriteFile(store.Path(digest), []byte(`{"changed":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(digest); err == nil {
		t.Fatal("corrupt plan was accepted")
	}
}

func TestCollectOrphans(t *testing.T) {
	t.Parallel()
	store, _ := New(filepath.Join(t.TempDir(), "plans"), "test")
	keep, _ := store.Put([]byte(`{"keep":true}`))
	orphan, _ := store.Put([]byte(`{"orphan":true}`))
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(store.Path(orphan), old, old); err != nil {
		t.Fatal(err)
	}
	removed, err := store.CollectOrphans(map[string]bool{keep: true}, time.Now().Add(-time.Hour))
	if err != nil || removed != 1 {
		t.Fatalf("CollectOrphans() = %d, %v", removed, err)
	}
	if _, err := store.Get(keep); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(orphan); err == nil {
		t.Fatal("orphan still exists")
	}
}

func TestStoreRejectsInvalidConfigurationAndBytes(t *testing.T) {
	t.Parallel()
	if _, err := New("", "test"); err == nil {
		t.Fatal("empty directory accepted")
	}
	store, _ := New(t.TempDir(), "test")
	for _, value := range [][]byte{nil, []byte(" value ")} {
		if _, err := store.Put(value); err == nil {
			t.Fatalf("Put(%q) succeeded", value)
		}
	}
	if _, err := store.Get("bad"); err == nil {
		t.Fatal("bad digest accepted")
	}
}
