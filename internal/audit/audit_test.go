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
		Client:              "agent",
		Operation:           "git.push.force",
		Target:              "dataset/acme/repo",
		Decision:            DecisionRefused,
		Reason:              "history rewrite refused",
		UpstreamStatus:      0,
		MatchedDenyRuleIDs:  []string{"deny-force"},
		MatchedAllowRuleIDs: []string{"allow-append"},
	})
	line := buf.String()
	for _, want := range []string{
		`"client":"agent"`,
		`"operation":"git.push.force"`,
		`"target":"dataset/acme/repo"`,
		`"decision":"refused"`,
		`"reason":"history rewrite refused"`,
		`"matched_deny_rule_ids":["deny-force"]`,
		`"matched_grant_rule_ids":[]`,
		`"matched_allow_rule_ids":["allow-append"]`,
		`"matched_request_rule_ids":[]`,
		`"grant_id":""`,
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("audit line %q missing %s", line, want)
		}
	}
}
