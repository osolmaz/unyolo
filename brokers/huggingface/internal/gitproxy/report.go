package gitproxy

import (
	"errors"
	"strings"

	"github.com/osolmaz/unyolo/git/protocol"
)

const defaultCascadeReason = "push refused by hf-broker because another ref failed"

// BuildRefusalReport returns a git-receive-pack result that stock git
// prints as a remote rejection instead of a generic HTTP error.
func BuildRefusalReport(req ReceivePackRequest, failures []RefFailure) ([]byte, error) {
	request := gitx.ReceivePackRequest{Capabilities: req.Capabilities}
	for _, command := range req.Commands {
		request.Commands = append(request.Commands, gitx.ReceivePackCommand{Old: command.Old, New: command.New, Ref: command.Ref})
	}
	sharedFailures := make([]gitx.ReceivePackFailure, 0, len(failures))
	for _, failure := range failures {
		sharedFailures = append(sharedFailures, gitx.ReceivePackFailure{Ref: failure.Ref, Reason: failure.Reason})
	}
	return gitx.BuildReceivePackRefusal("hf-broker", request, sharedFailures)
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
