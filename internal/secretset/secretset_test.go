package secretset

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestSetValidationAndMatching(t *testing.T) {
	secret := strings.Repeat("a", 24)
	set, err := New("client", map[string]string{" bob ": secret}, 16, nil)
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := set.Match(secret); !ok || id != "bob" {
		t.Fatalf("Match() = %q, %v", id, ok)
	}
	if _, ok := set.Match("wrong"); ok {
		t.Fatal("Match() accepted wrong secret")
	}
	forbidden := map[[sha256.Size]byte]struct{}{sha256.Sum256([]byte(secret)): {}}
	tests := []map[string]string{
		{},
		{"": secret},
		{"bad\nname": secret},
		{"bob": "short"},
		{"bob": secret, "alice": secret},
	}
	for _, secrets := range tests {
		if _, err := New("client", secrets, 16, nil); err == nil {
			t.Fatalf("New() accepted %#v", secrets)
		}
	}
	if _, err := New("operator", map[string]string{"onur": secret}, 16, forbidden); err == nil {
		t.Fatal("New() accepted forbidden secret")
	}
	if len(Hashes(map[string]string{"bob": secret})) != 1 {
		t.Fatal("Hashes() did not return one hash")
	}
}
