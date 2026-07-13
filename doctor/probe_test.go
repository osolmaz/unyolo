package doctor

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestProbeFileAccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !CanOpen(path) || !CanOpenForWrite(path) || CanOpen(path+"-missing") || CanOpenForWrite(path+"-missing") {
		t.Fatal("file probe result mismatch")
	}
}

func TestProbeUnixSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "probe.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if !DialUnix(context.Background(), path) || DialUnix(context.Background(), path+"-missing") {
		t.Fatal("Unix socket probe result mismatch")
	}
}
