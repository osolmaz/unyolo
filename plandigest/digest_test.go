package plandigest

import "testing"

func TestDigest(t *testing.T) {
	digest := Digest([]byte("plan"))
	if !Valid(digest) || Valid("invalid") || digest == Digest([]byte("other")) {
		t.Fatalf("digest validation failed: %q", digest)
	}
}
