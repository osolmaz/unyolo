package pktline

import (
	"errors"
	"testing"
)

func TestScannerAndAppendRoundTrip(t *testing.T) {
	var data []byte
	data = AppendString(data, "hello")
	data = Append(data, []byte("world"))
	data = AppendFlush(data)
	scanner := NewScanner(data)
	payload, kind, err := scanner.Next()
	if err != nil || kind != KindData || string(payload) != "hello" {
		t.Fatalf("first frame = %q %s %v", payload, kind, err)
	}
	if scanner.Offset() != len("0009hello") {
		t.Fatalf("Offset() = %d", scanner.Offset())
	}
	payload, kind, err = scanner.Next()
	if err != nil || kind != KindData || string(payload) != "world" {
		t.Fatalf("second frame = %q %s %v", payload, kind, err)
	}
	_, kind, err = scanner.Next()
	if err != nil || kind != KindFlush {
		t.Fatalf("flush frame kind=%s err=%v", kind, err)
	}
	_, _, err = scanner.Next()
	if !errors.Is(err, ErrDone) {
		t.Fatalf("final err = %v, want ErrDone", err)
	}
}

func TestScannerRejectsInvalidFrames(t *testing.T) {
	tests := [][]byte{
		[]byte("00xz"),
		[]byte("0003"),
		[]byte("0005"),
	}
	for _, input := range tests {
		scanner := NewScanner(input)
		if _, _, err := scanner.Next(); err == nil {
			t.Fatalf("Next(%q) succeeded, want error", input)
		}
	}
}
