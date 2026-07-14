package endpoint

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// ListenOptions controls direct Unix socket ownership and development behavior.
type ListenOptions struct {
	Development bool
	SocketMode  os.FileMode
}

// Listen acquires and verifies one server listener.
func Listen(value Endpoint, options ListenOptions) (net.Listener, error) {
	switch value.scheme {
	case SchemeTCP:
		return (&net.ListenConfig{}).Listen(context.Background(), "tcp", value.Address())
	case SchemeUnix:
		return listenUnix(value.path, options)
	case SchemeFD:
		return listenerFromFD(value.fd)
	case SchemeActivation:
		return activationListener(value.name)
	default:
		return nil, errors.New("endpoint is not initialized")
	}
}

func listenUnix(path string, options ListenOptions) (net.Listener, error) {
	if err := validateSocketParent(filepath.Dir(path), options.Development); err != nil {
		return nil, err
	}
	if err := removeStaleSocket(path); err != nil {
		return nil, err
	}
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on unix endpoint: %w", err)
	}
	mode := options.SocketMode.Perm()
	if mode == 0 {
		mode = 0o660
	}
	if mode&0o007 != 0 {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, errors.New("unix socket mode must not grant access to other users")
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("set unix socket mode: %w", err)
	}
	return &removingListener{Listener: listener, path: path}, nil
}

func validateSocketParent(path string, development bool) error {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean != path {
		return errors.New("unix socket parent must be absolute and normalized")
	}
	if development {
		return validateDirectory(path, effectiveUID())
	}
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(clean, current), current) {
		current = filepath.Join(current, component)
		expectedOwner := uint32(0)
		if current == clean {
			expectedOwner = effectiveUID()
		}
		if err := validateDirectory(current, expectedOwner); err != nil {
			return err
		}
	}
	return nil
}

func validateDirectory(path string, expectedOwner uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect unix socket parent: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("unix socket parent is not a trusted directory: %s", path)
	}
	if stat.Uid != expectedOwner {
		return fmt.Errorf("unix socket parent has unexpected owner: %s", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("unix socket parent is writable by group or other users: %s", path)
	}
	return nil
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect unix socket path: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || stat.Uid != effectiveUID() {
		return errors.New("existing unix endpoint is not an owned socket")
	}
	connection, dialErr := (&net.Dialer{Timeout: staleProbeTimeout}).DialContext(context.Background(), "unix", path)
	if dialErr == nil {
		_ = connection.Close()
		return errors.New("unix endpoint is already accepting connections")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale unix endpoint: %w", err)
	}
	return nil
}

func effectiveUID() uint32 {
	// #nosec G115 -- Unix effective UIDs are non-negative and represented by uint32 in Stat_t.
	return uint32(os.Geteuid())
}

func listenerFromFD(fd int) (net.Listener, error) {
	file := os.NewFile(uintptr(fd), "brokerkit-listener-"+strconv.Itoa(fd))
	if file == nil {
		return nil, errors.New("inherited listener descriptor is invalid")
	}
	listener, err := net.FileListener(file)
	closeErr := file.Close()
	if err != nil {
		return nil, fmt.Errorf("acquire inherited listener: %w", err)
	}
	if closeErr != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("close inherited descriptor duplicate: %w", closeErr)
	}
	if err := verifyListener(listener); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func verifyListener(listener net.Listener) error {
	switch listener.Addr().Network() {
	case "tcp", "tcp4", "tcp6", "unix":
		return nil
	default:
		return fmt.Errorf("inherited descriptor has unsupported network %q", listener.Addr().Network())
	}
}

type removingListener struct {
	net.Listener
	path string
}

func (listener *removingListener) Close() error {
	closeErr := listener.Listener.Close()
	removeErr := os.Remove(listener.path)
	if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return errors.Join(closeErr, removeErr)
	}
	return closeErr
}
