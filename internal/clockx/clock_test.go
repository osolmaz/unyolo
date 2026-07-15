package clockx

import (
	"testing"
	"time"
)

func TestOrNow(t *testing.T) {
	want := time.Unix(1, 0)
	clock := func() time.Time { return want }
	if got := OrNow(clock)(); !got.Equal(want) {
		t.Fatalf("configured clock = %v, want %v", got, want)
	}
	if OrNow(nil)().IsZero() {
		t.Fatal("default clock returned zero time")
	}
}
