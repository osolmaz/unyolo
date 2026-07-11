// Package gitproxy contains git smart-HTTP request parsing and
// append-only push enforcement helpers.
package gitproxy

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/gitproxy/pktline"
)

const zeroSHA = "0000000000000000000000000000000000000000"

// Command is one git-receive-pack ref update command.
type Command struct {
	Old string
	New string
	Ref string
}

// ReceivePackRequest is the parsed command prelude and raw pack payload
// from one git-receive-pack request body.
type ReceivePackRequest struct {
	Commands     []Command
	Capabilities map[string]bool
	Pack         []byte
}

// RefFailure is a refusal for a single ref update.
type RefFailure struct {
	Ref    string
	Reason string
}

// ParseReceivePack parses git-receive-pack's pkt-line command prelude and
// returns the trailing pack bytes unchanged.
func ParseReceivePack(body []byte) (ReceivePackRequest, error) {
	scanner := pktline.NewScanner(body)
	var req ReceivePackRequest
	req.Capabilities = map[string]bool{}
	first := true
	for {
		done, err := parseReceiveFrame(body, scanner, &req, &first)
		if err != nil {
			return ReceivePackRequest{}, err
		}
		if done {
			return req, nil
		}
	}
}

func parseReceiveFrame(body []byte, scanner *pktline.Scanner, req *ReceivePackRequest, first *bool) (bool, error) {
	payload, kind, err := scanner.Next()
	if errors.Is(err, pktline.ErrDone) {
		return false, errors.New("receive-pack command list missing flush")
	}
	if err != nil {
		return false, err
	}
	if kind == pktline.KindFlush {
		if err := skipPushOptions(body, scanner, req.Capabilities["push-options"]); err != nil {
			return false, err
		}
		req.Pack = body[scanner.Offset():]
		return true, nil
	}
	return false, appendReceiveCommand(req, bytes.TrimSuffix(payload, []byte{'\n'}), first)
}

func skipPushOptions(body []byte, scanner *pktline.Scanner, enabled bool) error {
	if !enabled || !looksLikePktLine(body, scanner.Offset()) {
		return nil
	}
	for {
		_, kind, err := scanner.Next()
		if errors.Is(err, pktline.ErrDone) {
			return errors.New("receive-pack push-options missing flush")
		}
		if err != nil {
			return err
		}
		if kind == pktline.KindFlush {
			return nil
		}
	}
}

func looksLikePktLine(body []byte, offset int) bool {
	if len(body)-offset < 4 {
		return false
	}
	for _, c := range body[offset : offset+4] {
		if !isHexPktLineDigit(c) {
			return false
		}
	}
	return true
}

func isHexPktLineDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func appendReceiveCommand(req *ReceivePackRequest, line []byte, first *bool) error {
	shallow, err := parseShallowLine(line)
	if err != nil || shallow {
		return err
	}
	if *first {
		line = splitCommandCapabilities(line, req.Capabilities)
		*first = false
	}
	command, err := parseCommandLine(string(line))
	if err != nil {
		return err
	}
	req.Commands = append(req.Commands, command)
	return nil
}

func splitCommandCapabilities(line []byte, caps map[string]bool) []byte {
	commandPart, capabilityPart, _ := bytes.Cut(line, []byte{0})
	for _, capName := range strings.Fields(string(capabilityPart)) {
		caps[capName] = true
	}
	return commandPart
}

func parseShallowLine(line []byte) (bool, error) {
	sha, ok := bytes.CutPrefix(line, []byte("shallow "))
	if !ok {
		return false, nil
	}
	if !validSHA(string(sha)) {
		return false, fmt.Errorf("receive-pack shallow line %q: invalid object id", line)
	}
	return true, nil
}

func parseCommandLine(line string) (Command, error) {
	fields := strings.Fields(line)
	if len(fields) != 3 {
		return Command{}, fmt.Errorf("receive-pack command %q: expected old new ref", line)
	}
	if !validSHA(fields[0]) || !validSHA(fields[1]) {
		return Command{}, fmt.Errorf("receive-pack command %q: invalid object id", line)
	}
	if !ValidRefName(fields[2]) {
		return Command{}, fmt.Errorf("receive-pack command %q: invalid ref", line)
	}
	return Command{Old: fields[0], New: fields[1], Ref: fields[2]}, nil
}

// ValidRefName reports whether ref is a conservative git ref name accepted by
// the broker parser.
func ValidRefName(ref string) bool {
	return strings.HasPrefix(ref, "refs/") && !strings.Contains(ref, "..") && !strings.ContainsAny(ref, " \t\r\n")
}

func validSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, c := range value {
		if !isHexSHAChar(c) {
			return false
		}
	}
	return true
}

func isHexSHAChar(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// IsZeroSHA reports whether value is git's all-zero ref marker.
func IsZeroSHA(value string) bool {
	return value == zeroSHA
}

// CheckStaticRules applies append-only rules that do not require a
// mirror lookup.
func CheckStaticRules(commands []Command) []RefFailure {
	var failures []RefFailure
	for _, command := range commands {
		switch {
		case IsZeroSHA(command.New):
			failures = append(failures, RefFailure{Ref: command.Ref, Reason: "deletion refused"})
		case strings.HasPrefix(command.Ref, "refs/replace/"):
			failures = append(failures, RefFailure{Ref: command.Ref, Reason: "replace refs refused"})
		case strings.HasPrefix(command.Ref, "refs/tags/") && !IsZeroSHA(command.Old):
			failures = append(failures, RefFailure{Ref: command.Ref, Reason: "tag update refused"})
		}
	}
	return failures
}
