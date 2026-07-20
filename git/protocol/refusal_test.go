package gitx

import (
	"bytes"
	"strings"
	"testing"
)

func TestBuildReceivePackRefusal(t *testing.T) {
	request := ReceivePackRequest{
		Commands: []ReceivePackCommand{
			{Ref: "refs/tags/v1"},
			{Ref: "refs/heads/main"},
		},
		Capabilities: map[string]bool{"side-band-64k": true},
	}
	report, err := BuildReceivePackRefusal("gh-broker", request, []ReceivePackFailure{{
		Ref: "refs/tags/v1", Reason: "approval required (grant-1)\napprove and retry",
	}})
	if err != nil {
		t.Fatalf("BuildReceivePackRefusal() error = %v", err)
	}
	for _, expected := range []string{
		"gh-broker: approval required (grant-1) approve and retry",
		"ng refs/tags/v1 gh-broker: approval required (grant-1) approve and retry",
		"ng refs/heads/main gh-broker: push refused by gh-broker because another ref failed",
	} {
		if !bytes.Contains(report, []byte(expected)) {
			t.Fatalf("report does not contain %q: %q", expected, report)
		}
	}
}

func TestBuildReceivePackRefusalRejectsOversizedStatus(t *testing.T) {
	request := ReceivePackRequest{Commands: []ReceivePackCommand{{Ref: "refs/heads/" + strings.Repeat("x", MaxPktLinePayload)}}}
	if _, err := BuildReceivePackRefusal("gh-broker", request, nil); err == nil {
		t.Fatal("BuildReceivePackRefusal() accepted an oversized status line")
	}
}
