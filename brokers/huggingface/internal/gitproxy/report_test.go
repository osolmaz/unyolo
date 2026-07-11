package gitproxy

import (
	"errors"
	"strings"
	"testing"

	"github.com/osolmaz/hf-broker/internal/gitproxy/pktline"
)

func TestReceivePackAcceptedParsesReports(t *testing.T) {
	req := ReceivePackRequest{Commands: []Command{{Ref: "refs/heads/main"}}, Capabilities: map[string]bool{}}
	body := pktline.AppendString(nil, "unpack ok\n")
	body = pktline.AppendString(body, "ok refs/heads/main\n")
	body = pktline.AppendFlush(body)
	accepted, reason, err := ReceivePackAccepted(req, body)
	if err != nil || !accepted || reason != "" {
		t.Fatalf("plain accepted = %v reason=%q err=%v", accepted, reason, err)
	}

	rejected := pktline.AppendString(nil, "unpack ok\n")
	rejected = pktline.AppendString(rejected, "ng refs/heads/main upstream rejected\n")
	rejected = pktline.AppendFlush(rejected)
	accepted, reason, err = ReceivePackAccepted(req, rejected)
	if err != nil || accepted || !strings.Contains(reason, "upstream rejected") {
		t.Fatalf("plain rejected = %v reason=%q err=%v", accepted, reason, err)
	}
}

func TestReceivePackAcceptedParsesSideBandReports(t *testing.T) {
	req := ReceivePackRequest{
		Commands:     []Command{{Ref: "refs/heads/main"}},
		Capabilities: map[string]bool{"side-band-64k": true},
	}
	status := pktline.AppendString(nil, "unpack ok\n")
	status = pktline.AppendString(status, "ok refs/heads/main\n")
	status = pktline.AppendFlush(status)
	body := appendTestBand(nil, 2, "counting objects\n")
	body = appendTestBandBytes(body, 1, status)
	body = pktline.AppendFlush(body)
	accepted, reason, err := ReceivePackAccepted(req, body)
	if err != nil || !accepted || reason != "" {
		t.Fatalf("side-band accepted = %v reason=%q err=%v", accepted, reason, err)
	}

	fatal := appendTestBand(nil, 3, "fatal upstream failure\n")
	fatal = pktline.AppendFlush(fatal)
	accepted, reason, err = ReceivePackAccepted(req, fatal)
	if err != nil || accepted || !strings.Contains(reason, "fatal upstream failure") {
		t.Fatalf("side-band fatal = %v reason=%q err=%v", accepted, reason, err)
	}
}

func TestBuildRefusalReportChunksLargeSideBandStatus(t *testing.T) {
	req := ReceivePackRequest{Capabilities: map[string]bool{"side-band-64k": true}}
	for i := 0; i < 2000; i++ {
		req.Commands = append(req.Commands, Command{Ref: "refs/heads/branch-" + strings.Repeat("x", i%64)})
	}
	report := BuildRefusalReport(req, []RefFailure{{Ref: req.Commands[0].Ref, Reason: "history rewrite refused"}})
	scanner := pktline.NewScanner(report)
	bandOneChunks := 0
	for {
		payload, kind, err := scanner.Next()
		if errors.Is(err, pktline.ErrDone) {
			break
		}
		if err != nil {
			t.Fatalf("outer side-band report is invalid: %v", err)
		}
		if kind == pktline.KindData && len(payload) > 0 && payload[0] == 1 {
			bandOneChunks++
		}
	}
	if bandOneChunks < 2 {
		t.Fatalf("band 1 chunks = %d, want multiple chunks", bandOneChunks)
	}
	accepted, reason, err := ReceivePackAccepted(req, report)
	if err != nil || accepted || !strings.Contains(reason, "history rewrite refused") {
		t.Fatalf("large report accepted=%v reason=%q err=%v", accepted, reason, err)
	}
}

func appendTestBand(dst []byte, band byte, payload string) []byte {
	return appendTestBandBytes(dst, band, []byte(payload))
}

func appendTestBandBytes(dst []byte, band byte, payload []byte) []byte {
	data := append([]byte{band}, payload...)
	return pktline.Append(dst, data)
}
