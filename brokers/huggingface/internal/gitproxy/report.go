package gitproxy

import (
	"errors"
	"strings"

	"github.com/osolmaz/brokerkit/git/protocol"
)

const defaultCascadeReason = "push refused by hf-broker because another ref failed"

const maxSideBandDataPayload = gitx.MaxPktLinePayload - 1

// BuildRefusalReport returns a git-receive-pack result that stock git
// prints as a remote rejection instead of a generic HTTP error.
func BuildRefusalReport(req ReceivePackRequest, failures []RefFailure) ([]byte, error) {
	reasons := map[string]string{}
	firstReason := "push refused"
	for i, failure := range failures {
		reason := cleanReason(failure.Reason)
		if i == 0 {
			firstReason = reason
		}
		reasons[failure.Ref] = reason
	}
	sideBand := req.Capabilities["side-band-64k"] || req.Capabilities["side-band"]
	status, err := appendRefusalStatus(nil, req.Commands, reasons)
	if err != nil {
		return nil, err
	}
	status = gitx.AppendFlushPkt(status)
	var out []byte
	if sideBand {
		out, err = appendBandString(out, 2, "hf-broker: "+firstReason+"\n")
		if err != nil {
			return nil, err
		}
		out, err = appendBandBytes(out, 1, status)
		return gitx.AppendFlushPkt(out), err
	}
	return status, nil
}

func appendRefusalStatus(dst []byte, commands []Command, reasons map[string]string) ([]byte, error) {
	dst, err := gitx.AppendPktLineString(dst, "unpack ok\n")
	if err != nil {
		return nil, err
	}
	return appendPlainFailures(dst, commands, reasons)
}

func appendPlainFailures(dst []byte, commands []Command, reasons map[string]string) ([]byte, error) {
	for _, command := range commands {
		var err error
		dst, err = gitx.AppendPktLineString(dst, "ng "+command.Ref+" hf-broker: "+reasonForRef(command.Ref, reasons)+"\n")
		if err != nil {
			return nil, err
		}
	}
	return dst, nil
}

func reasonForRef(ref string, reasons map[string]string) string {
	reason := reasons[ref]
	if reason == "" {
		return defaultCascadeReason
	}
	return reason
}

func appendBandString(dst []byte, band byte, payload string) ([]byte, error) {
	return appendBandBytes(dst, band, []byte(payload))
}

func appendBandBytes(dst []byte, band byte, payload []byte) ([]byte, error) {
	for len(payload) > 0 {
		n := len(payload)
		if n > maxSideBandDataPayload {
			n = maxSideBandDataPayload
		}
		data := append([]byte{band}, payload[:n]...)
		var err error
		dst, err = gitx.AppendPktLine(dst, data)
		if err != nil {
			return nil, err
		}
		payload = payload[n:]
	}
	return dst, nil
}

func cleanReason(reason string) string {
	reason = strings.TrimSpace(reason)
	reason = strings.ReplaceAll(reason, "\n", " ")
	reason = strings.ReplaceAll(reason, "\r", " ")
	if reason == "" {
		return "refused"
	}
	return reason
}

// ReceivePackAccepted reports whether an upstream git-receive-pack result
// accepted every ref update in req.
func ReceivePackAccepted(req ReceivePackRequest, body []byte) (bool, string, error) {
	statusBody, fatal, err := receivePackStatusBody(req, body)
	if err != nil {
		return false, "", err
	}
	if fatal != "" {
		return false, cleanReason(fatal), nil
	}
	return parseReceivePackStatus(req, statusBody)
}

func receivePackStatusBody(req ReceivePackRequest, body []byte) ([]byte, string, error) {
	if !receivePackUsesSideBand(req) {
		return body, "", nil
	}
	return collectReceivePackSideBand(body)
}

func collectReceivePackSideBand(body []byte) ([]byte, string, error) {
	var status []byte
	scanner := gitx.NewScanner(body)
	for {
		payload, flush, err := scanner.Next()
		if errors.Is(err, gitx.ErrDone) {
			break
		}
		if err != nil {
			return nil, "", err
		}
		if flush || len(payload) == 0 {
			continue
		}
		next, fatal := receivePackSideBandPayload(payload)
		if fatal != "" {
			return nil, fatal, nil
		}
		status = append(status, next...)
	}
	return status, "", nil
}

func receivePackSideBandPayload(payload []byte) ([]byte, string) {
	switch payload[0] {
	case 1:
		return payload[1:], ""
	case 2:
		return nil, ""
	case 3:
		return nil, string(payload[1:])
	default:
		return nil, ""
	}
}

func parseReceivePackStatus(req ReceivePackRequest, body []byte) (bool, string, error) {
	status := receivePackStatus{refs: map[string]bool{}}
	scanner := gitx.NewScanner(body)
	for {
		payload, flush, err := scanner.Next()
		if errors.Is(err, gitx.ErrDone) {
			break
		}
		if err != nil {
			return false, "", err
		}
		if flush {
			continue
		}
		lines := strings.Split(string(payload), "\n")
		if reason := status.consume(lines); reason != "" {
			return false, reason, nil
		}
	}
	return status.accepted(req)
}

type receivePackStatus struct {
	unpackOK bool
	refs     map[string]bool
}

func receivePackUsesSideBand(req ReceivePackRequest) bool {
	return req.Capabilities["side-band-64k"] || req.Capabilities["side-band"]
}

func (s *receivePackStatus) consume(lines []string) string {
	for _, line := range lines {
		reason := s.consumeLine(line)
		if reason != "" {
			return reason
		}
	}
	return ""
}

func (s *receivePackStatus) consumeLine(line string) string {
	line = strings.TrimSpace(line)
	switch {
	case line == "":
		return ""
	case line == "unpack ok":
		s.unpackOK = true
	case strings.HasPrefix(line, "unpack "):
		return cleanReason(strings.TrimPrefix(line, "unpack "))
	case strings.HasPrefix(line, "ok "):
		s.refs[strings.TrimSpace(strings.TrimPrefix(line, "ok "))] = true
	case strings.HasPrefix(line, "ng "):
		return cleanReason(strings.TrimPrefix(line, "ng "))
	}
	return ""
}

func (s receivePackStatus) accepted(req ReceivePackRequest) (bool, string, error) {
	if !s.unpackOK {
		return false, "upstream receive-pack report missing unpack status", nil
	}
	for _, command := range req.Commands {
		if !s.refs[command.Ref] {
			return false, "upstream receive-pack report missing ref status", nil
		}
	}
	return true, "", nil
}
