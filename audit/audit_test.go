package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRecordJSONL(t *testing.T) {
	var buf bytes.Buffer
	now := time.Date(2026, 7, 8, 1, 2, 3, 0, time.UTC)
	writer := New(&buf).WithClock(func() time.Time { return now })
	if err := writer.Record(Event{
		Broker:         "gh-broker",
		Client:         "bob",
		Operation:      "pr.create",
		Target:         "repo/osolmaz/demo",
		Decision:       "allow",
		MatchedRuleIDs: []string{"bob-pr"},
	}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	var decoded Event
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &decoded); err != nil {
		t.Fatalf("audit JSON = %q: %v", buf.String(), err)
	}
	if decoded.Time != now || decoded.Broker != "gh-broker" || decoded.MatchedRuleIDs[0] != "bob-pr" {
		t.Fatalf("decoded event = %+v", decoded)
	}
}

func TestRecordDoesNotInventSecretFields(t *testing.T) {
	var buf bytes.Buffer
	err := New(&buf).Record(Event{Broker: "sudo-broker", ErrorCode: "policy_denied"})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"authorization", "token", "secret", "password"} {
		if strings.Contains(strings.ToLower(buf.String()), forbidden) {
			t.Fatalf("audit output contains %q: %s", forbidden, buf.String())
		}
	}
}

func TestRecordRedactsSecretMetadata(t *testing.T) {
	var buf bytes.Buffer
	err := New(&buf).Record(Event{
		Broker:     "gh-broker",
		Attrs:      map[string]string{"ref": "refs/heads/main", "decision_token": "token-value"},
		Extensions: map[string]string{"authorization": "Bearer upstream", "request_id": "req-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, forbidden := range []string{"decision_token", "token-value", "authorization", "Bearer upstream"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("audit output contains %q: %s", forbidden, out)
		}
	}
	if !strings.Contains(out, "refs/heads/main") || !strings.Contains(out, "req-1") {
		t.Fatalf("audit output lost safe metadata: %s", out)
	}
}
