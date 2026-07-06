package audit

import (
	"bytes"
	"strings"
	"testing"
)

func TestRecordWritesStructuredAuditLine(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf)
	logger.Record(Entry{
		Client:         "agent",
		Operation:      "git_receive_pack",
		Target:         "dataset/acme/repo",
		Decision:       DecisionRefused,
		Reason:         "history rewrite refused",
		UpstreamStatus: 0,
	})
	line := buf.String()
	for _, want := range []string{
		`"client":"agent"`,
		`"operation":"git_receive_pack"`,
		`"target":"dataset/acme/repo"`,
		`"decision":"refused"`,
		`"reason":"history rewrite refused"`,
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("audit line %q missing %s", line, want)
		}
	}
}
