//go:build linux || darwin

package executorserver

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultPeerUID(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	result := make(chan struct {
		uid uint32
		err error
	}, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		if err != nil {
			result <- struct {
				uid uint32
				err error
			}{err: err}
			return
		}
		defer func() { _ = connection.Close() }()
		uid, err := DefaultPeerUID(connection)
		result <- struct {
			uid uint32
			err error
		}{uid: uid, err: err}
	}()
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	got := <-result
	if got.err != nil || got.uid != uint32(os.Getuid()) { // #nosec G115 -- Unix uid is non-negative.
		t.Fatalf("DefaultPeerUID() = %d, %v", got.uid, got.err)
	}
}
