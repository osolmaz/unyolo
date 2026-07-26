//go:build linux

package setup

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/deployment/flow"
	"golang.org/x/sys/unix"
)

func TestInteractiveSelectRestoresTerminalAtSupportedWidths(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("FORCE_COLOR", "1")
	for _, width := range []int{60, 80, 120} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			master, slave := openPTY(t)
			input, sendInput, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = input.Close(); _ = sendInput.Close(); _ = master.Close(); _ = slave.Close() }()
			var captured bytes.Buffer
			drainDone := make(chan struct{})
			go func() {
				_, _ = io.Copy(&captured, master)
				close(drainDone)
			}()
			prompter := New(Options{Input: input, Output: slave, Width: width})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				value, err := prompter.Select(ctx, flow.SelectPrompt{
					Message: "Choose", InitialValue: "one",
					Options: []flow.Option{{Value: "one", Label: "One"}, {Value: "two", Label: "Two"}},
				})
				if err == nil && value != "one" {
					err = fmt.Errorf("selected %q", value)
				}
				result <- err
			}()
			time.Sleep(100 * time.Millisecond)
			if _, err := sendInput.Write([]byte("\r")); err != nil {
				t.Fatal(err)
			}
			if err := sendInput.Close(); err != nil {
				t.Fatal(err)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			if err := prompter.Close(); err != nil {
				t.Fatal(err)
			}
			_ = slave.Close()
			select {
			case <-drainDone:
			case <-time.After(time.Second):
				_ = master.Close()
				<-drainDone
			}
			if !bytes.Contains(captured.Bytes(), []byte("\x1b[?25h")) {
				t.Fatalf("terminal output did not restore the cursor: %q", captured.Bytes())
			}
		})
	}
}

func openPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	slaveFD, err := unix.Open(fmt.Sprintf("/dev/pts/%d", number), unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	return os.NewFile(uintptr(fd), "pty-master"), os.NewFile(uintptr(slaveFD), "pty-slave")
}
