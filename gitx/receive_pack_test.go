package gitx

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestParseReceivePackCommands(t *testing.T) {
	body := pkt("0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 refs/heads/feature\x00 report-status\n") +
		pkt("1111111111111111111111111111111111111111 2222222222222222222222222222222222222222 refs/heads/main\n") +
		pkt("2222222222222222222222222222222222222222 0000000000000000000000000000000000000000 refs/heads/old\n") +
		"0000"
	commands, err := ParseReceivePackCommands(bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("ParseReceivePackCommands() error = %v", err)
	}
	if len(commands) != 3 {
		t.Fatalf("commands = %+v, want 3", commands)
	}
	if commands[0].Kind != RefUpdateBranchCreate || commands[1].Kind != RefUpdateBranchUpdate || commands[2].Kind != RefUpdateRefDelete {
		t.Fatalf("command kinds = %+v", commands)
	}
}

func TestClassifyTagsAndOtherRefs(t *testing.T) {
	cases := []struct {
		name string
		cmd  ReceivePackCommand
		want RefUpdateKind
	}{
		{name: "tag create", cmd: ReceivePackCommand{Old: strings.Repeat("0", 40), New: "1", Ref: "refs/tags/v1"}, want: RefUpdateTagCreate},
		{name: "tag update", cmd: ReceivePackCommand{Old: "1", New: "2", Ref: "refs/tags/v1"}, want: RefUpdateTagUpdate},
		{name: "other", cmd: ReceivePackCommand{Old: "1", New: "2", Ref: "refs/notes/commits"}, want: RefUpdateOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.cmd); got != tc.want {
				t.Fatalf("classify() = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestClassifySHA256ZeroObjectIDs(t *testing.T) {
	zero := strings.Repeat("0", 64)
	cases := []struct {
		name string
		cmd  ReceivePackCommand
		want RefUpdateKind
	}{
		{name: "branch create", cmd: ReceivePackCommand{Old: zero, New: strings.Repeat("1", 64), Ref: "refs/heads/feature"}, want: RefUpdateBranchCreate},
		{name: "branch delete", cmd: ReceivePackCommand{Old: strings.Repeat("1", 64), New: zero, Ref: "refs/heads/feature"}, want: RefUpdateRefDelete},
		{name: "tag create", cmd: ReceivePackCommand{Old: zero, New: strings.Repeat("1", 64), Ref: "refs/tags/v1"}, want: RefUpdateTagCreate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.cmd); got != tc.want {
				t.Fatalf("classify() = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestParseReceivePackRejectsMalformedCommand(t *testing.T) {
	_, err := ParseReceivePackCommands(bytes.NewBufferString(pkt("bad command\n")))
	if err == nil {
		t.Fatal("ParseReceivePackCommands() error = nil, want malformed command")
	}
}

func TestParseReceivePackSkipsShallowRecords(t *testing.T) {
	body := pkt("shallow 1111111111111111111111111111111111111111\n") +
		pkt("0000000000000000000000000000000000000000 2222222222222222222222222222222222222222 refs/heads/feature\n") +
		"0000"
	commands, err := ParseReceivePackCommands(bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("ParseReceivePackCommands() error = %v", err)
	}
	if len(commands) != 1 || commands[0].Ref != "refs/heads/feature" {
		t.Fatalf("commands = %+v, want one feature command", commands)
	}
}

func TestParseReceivePackRejectsInvalidShallowRecord(t *testing.T) {
	_, err := ParseReceivePackCommands(bytes.NewBufferString(pkt("shallow bad\n")))
	if err == nil {
		t.Fatal("ParseReceivePackCommands() error = nil, want invalid shallow object id")
	}
}

func TestParseReceivePackRejectsInvalidObjectIDs(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{name: "short old", payload: "bad 1111111111111111111111111111111111111111 refs/heads/main\n"},
		{name: "non hex old", payload: "gggggggggggggggggggggggggggggggggggggggg 1111111111111111111111111111111111111111 refs/heads/main\n"},
		{name: "short new", payload: "0000000000000000000000000000000000000000 old refs/heads/main\n"},
		{name: "mixed widths", payload: strings.Repeat("0", 40) + " " + strings.Repeat("1", 64) + " refs/heads/main\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseReceivePackCommands(bytes.NewBufferString(pkt(tc.payload)))
			if err == nil {
				t.Fatal("ParseReceivePackCommands() error = nil, want invalid object id")
			}
		})
	}
}

func TestParseReceivePackRejectsInvalidRefNames(t *testing.T) {
	cases := []struct {
		name string
		ref  string
	}{
		{name: "not refs namespace", ref: "heads/main"},
		{name: "empty component", ref: "refs/heads//main"},
		{name: "hidden component", ref: "refs/heads/.main"},
		{name: "dot dot", ref: "refs/heads/feature..main"},
		{name: "tilde", ref: "refs/heads/foo~bar"},
		{name: "caret", ref: "refs/heads/foo^bar"},
		{name: "colon", ref: "refs/heads/foo:bar"},
		{name: "question", ref: "refs/heads/foo?bar"},
		{name: "asterisk", ref: "refs/heads/foo*bar"},
		{name: "open bracket", ref: "refs/heads/foo[bar"},
		{name: "backslash", ref: `refs/heads/foo\bar`},
		{name: "lock suffix", ref: "refs/heads/main.lock"},
		{name: "reflog selector", ref: "refs/heads/main@{1}"},
		{name: "trailing dot", ref: "refs/heads/main."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseReceivePackCommands(bytes.NewBufferString(pkt(strings.Repeat("0", 40) + " " + strings.Repeat("1", 40) + " " + tc.ref + "\n")))
			if err == nil {
				t.Fatal("ParseReceivePackCommands() error = nil, want invalid ref")
			}
		})
	}
}

func TestParseReceivePackPreservesPackStream(t *testing.T) {
	stream := bytes.NewBufferString(pkt("0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 refs/heads/feature\n") + "0000PACKDATA")
	if _, err := ParseReceivePackCommands(stream); err != nil {
		t.Fatalf("ParseReceivePackCommands() error = %v", err)
	}
	remaining, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(remaining) != "PACKDATA" {
		t.Fatalf("remaining stream = %q, want PACKDATA", string(remaining))
	}
}

func pkt(payload string) string {
	return fourHex(len(payload)+4) + payload
}

func fourHex(value int) string {
	const digits = "0123456789abcdef"
	return string([]byte{
		digits[(value>>12)&0xf],
		digits[(value>>8)&0xf],
		digits[(value>>4)&0xf],
		digits[value&0xf],
	})
}
