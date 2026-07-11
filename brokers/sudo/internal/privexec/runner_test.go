package privexec

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestOutputBudgetCapsCombinedStreams(t *testing.T) {
	t.Parallel()
	budget := newOutputBudget(5)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	killed := 0
	budget.setKill(func() { killed++ })
	_, _ = budget.writer(&stdout).Write([]byte("abc"))
	_, _ = budget.writer(&stderr).Write([]byte("def"))
	_, _ = budget.writer(&stdout).Write([]byte("more"))
	if stdout.String() != "abc" || stderr.String() != "de" || killed != 1 || !budget.truncatedOutput() {
		t.Fatalf("stdout=%q stderr=%q killed=%d truncated=%v", stdout.String(), stderr.String(), killed, budget.truncatedOutput())
	}
}

func TestRunInternalChildIsNotPublicPrivilegePath(t *testing.T) {
	t.Parallel()
	handled, err := RunInternalChild(nil)
	if handled || err != nil {
		t.Fatalf("empty child = %v, %v", handled, err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root can enter the internal child path")
	}
	if handled, err := RunInternalChild([]string{"--internal-exec", "3"}); !handled || err == nil || !strings.Contains(err.Error(), "requires root") {
		if !handled || err == nil {
			t.Fatalf("unprivileged child = %v, %v", handled, err)
		}
	}
}
