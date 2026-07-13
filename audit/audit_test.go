package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
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

func TestRecordPreservesCategorizedRequestFields(t *testing.T) {
	var buf bytes.Buffer
	err := New(&buf).Record(Event{
		Broker:                "hf-broker",
		Client:                "agent",
		Operation:             "git.push.force",
		Target:                "dataset/acme/repo",
		Decision:              DecisionGrantUsed,
		Reason:                "operator grant used",
		MatchedDenyRuleIDs:    []string{"deny-force"},
		MatchedGrantRuleIDs:   []string{"grant-1"},
		MatchedAllowRuleIDs:   []string{"allow-push"},
		MatchedRequestRuleIDs: []string{"request-force"},
		GrantID:               "grant-1",
		PlanDigest:            "sha256:plan",
		UpstreamStatus:        200,
	})
	if err != nil {
		t.Fatal(err)
	}
	var event Event
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &event); err != nil {
		t.Fatal(err)
	}
	if event.Broker != "hf-broker" || event.UpstreamStatus != 200 || event.PlanDigest != "sha256:plan" ||
		len(event.MatchedDenyRuleIDs) != 1 || len(event.MatchedGrantRuleIDs) != 1 ||
		len(event.MatchedAllowRuleIDs) != 1 || len(event.MatchedRequestRuleIDs) != 1 {
		t.Fatalf("categorized event = %+v", event)
	}
}

func TestRecordNormalizesRuleCategories(t *testing.T) {
	var buf bytes.Buffer
	if err := New(&buf).Record(Event{Broker: "hf-broker"}); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"matched_deny_rule_ids", "matched_grant_rule_ids", "matched_allow_rule_ids", "matched_request_rule_ids"} {
		if !strings.Contains(buf.String(), `"`+field+`":[]`) {
			t.Fatalf("audit output missing empty %s: %s", field, buf.String())
		}
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

func TestRecordBoundsMetadata(t *testing.T) {
	metadata := map[string]string{
		strings.Repeat("k", maxMetadataKey+1): "oversized key",
		"token":                               "secret",
		"00-value":                            strings.Repeat("v", maxMetadataValue-1) + "\xffmore",
	}
	for index := range maxMetadataFields + 10 {
		metadata[fmt.Sprintf("field-%02d", index)] = "safe"
	}
	var buf bytes.Buffer
	if err := New(&buf).Record(Event{Broker: "test", Extensions: metadata}); err != nil {
		t.Fatal(err)
	}
	var event Event
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &event); err != nil {
		t.Fatal(err)
	}
	if len(event.Extensions) != maxMetadataFields {
		t.Fatalf("extension fields = %d, want %d", len(event.Extensions), maxMetadataFields)
	}
	for key, value := range event.Extensions {
		if len(key) > maxMetadataKey || len(value) > maxMetadataValue || strings.ToValidUTF8(value, "") != value {
			t.Fatalf("unbounded extension %q=%q", key, value)
		}
	}
}
