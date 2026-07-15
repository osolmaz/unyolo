//go:build linux

package endpoint

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestSystemdActivationEnvironmentValidation(t *testing.T) {
	t.Setenv("LISTEN_PID", os.Getenv("LISTEN_PID"))
	t.Setenv("LISTEN_FDS", os.Getenv("LISTEN_FDS"))
	t.Setenv("LISTEN_FDNAMES", os.Getenv("LISTEN_FDNAMES"))

	t.Setenv("LISTEN_PID", "not-a-pid")
	t.Setenv("LISTEN_FDS", "1")
	if _, err := systemdActivationCount(); err == nil {
		t.Fatal("invalid LISTEN_PID accepted")
	}

	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	t.Setenv("LISTEN_FDS", "2")
	count, err := systemdActivationCount()
	if err != nil || count != 2 {
		t.Fatalf("systemdActivationCount() = %d, %v", count, err)
	}

	if _, err := activationNamesFromEnv(2, 1); err == nil {
		t.Fatal("activationNamesFromEnv accepted incomplete names")
	}
	t.Setenv("LISTEN_FDNAMES", "agent:operator")
	names, err := activationNamesFromEnv(2, 2)
	if err != nil || len(names) != 2 || names[0] != "agent" || names[1] != "operator" {
		t.Fatalf("activationNamesFromEnv() = %v, %v", names, err)
	}
}

func TestExpectedActivationNamesRejectsDuplicates(t *testing.T) {
	if _, err := expectedActivationNames([]string{"agent", "agent"}); err == nil {
		t.Fatal("duplicate activation name accepted")
	}
	wanted, err := expectedActivationNames([]string{"agent", "operator"})
	if err != nil || len(wanted) != 2 {
		t.Fatalf("expectedActivationNames() = %v, %v", wanted, err)
	}
}

func TestAcquireSystemdListenersClosesPartialSet(t *testing.T) {
	first := &fakeListener{address: fakeAddress("unix")}
	opened := 0
	open := func(fd int) (net.Listener, error) {
		opened++
		if fd == 3 {
			return first, nil
		}
		return nil, errors.New("boom")
	}

	wanted := map[string]struct{}{"agent": {}, "operator": {}}
	if _, err := acquireSystemdListeners([]string{"agent", "operator"}, wanted, open); err == nil {
		t.Fatal("descriptor failure accepted")
	}
	if opened != 2 || !first.closed {
		t.Fatalf("opened=%d closed=%t", opened, first.closed)
	}
}

func TestActivationListenersUsesEnvironmentAndDescriptors(t *testing.T) {
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	t.Setenv("LISTEN_FDS", "1")
	t.Setenv("LISTEN_FDNAMES", "agent")
	open := func(fd int) (net.Listener, error) {
		if fd != 3 {
			t.Fatalf("fd = %d, want 3", fd)
		}
		return &fakeListener{address: fakeAddress("unix")}, nil
	}

	listeners, err := activationListenersWith([]string{"agent"}, open)
	if err != nil || listeners["agent"] == nil {
		t.Fatalf("activationListeners() = %v, %v", listeners, err)
	}
	_ = listeners["agent"].Close()
}

func TestListenActivationEndpointUsesEnvironment(t *testing.T) {
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	t.Setenv("LISTEN_FDS", "1")
	t.Setenv("LISTEN_FDNAMES", "agent")
	open := func(fd int) (net.Listener, error) {
		return &fakeListener{address: fakeAddress("unix")}, nil
	}

	endpoint, err := Parse("activation://agent", ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := listenWith(endpoint, ListenOptions{}, func(names []string) (map[string]net.Listener, error) {
		return activationListenersWith(names, open)
	})
	if err != nil || listener == nil {
		t.Fatalf("Listen(activation) = %v, %v", listener, err)
	}
	_ = listener.Close()
}

func TestListenSetActivationAcquiresCompleteSet(t *testing.T) {
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	t.Setenv("LISTEN_FDS", "1")
	t.Setenv("LISTEN_FDNAMES", "agent")
	open := func(fd int) (net.Listener, error) {
		return &fakeListener{address: fakeAddress("unix")}, nil
	}

	listeners := map[string]net.Listener{"logical-agent": nil}
	err := acquireActivatedSetWith(listeners, []string{"agent"}, map[string]string{"agent": "logical-agent"}, func(names []string) (map[string]net.Listener, error) {
		return activationListenersWith(names, open)
	})
	if err != nil || listeners["logical-agent"] == nil {
		t.Fatalf("ListenSet(activation) = %v, %v", listeners, err)
	}
	_ = CloseSet(listeners)
}

func TestListenerFromFileAcceptsListenerFile(t *testing.T) {
	base, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	file, err := base.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := listenerFromFile(file)
	if err != nil {
		t.Fatal(err)
	}
	_ = listener.Close()
}

func TestListenerFromFileRejectsUnsupportedNetwork(t *testing.T) {
	file, err := os.OpenFile(os.DevNull, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := listenerFromFile(file); err == nil {
		t.Fatal("non-listener file accepted")
	}
}

func TestValidateSocketParentChainRejectsUntrustedParents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "socket-parent")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateSocketParentChain(path); err == nil {
		t.Fatal("non-root parent chain accepted")
	}
}

type fakeListener struct {
	address net.Addr
	closed  bool
}

func (listener *fakeListener) Accept() (net.Conn, error) { return nil, errors.New("closed") }
func (listener *fakeListener) Close() error {
	listener.closed = true
	return nil
}
func (listener *fakeListener) Addr() net.Addr { return listener.address }

type fakeAddress string

func (address fakeAddress) Network() string { return string(address) }
func (address fakeAddress) String() string  { return string(address) + "://test" }
