package gitx

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	sha1ObjectIDLength   = 40
	sha256ObjectIDLength = 64
)

// RefUpdateKind is the policy-relevant class of a receive-pack command.
type RefUpdateKind string

const (
	RefUpdateBranchCreate RefUpdateKind = "branch_create"
	RefUpdateBranchUpdate RefUpdateKind = "branch_update"
	RefUpdateRefDelete    RefUpdateKind = "ref_delete"
	RefUpdateTagCreate    RefUpdateKind = "tag_create"
	RefUpdateTagUpdate    RefUpdateKind = "tag_update"
	RefUpdateOther        RefUpdateKind = "other"
)

// ReceivePackCommand is one parsed receive-pack ref update command.
type ReceivePackCommand struct {
	Old  string
	New  string
	Ref  string
	Kind RefUpdateKind
}

// ReceivePackRequest is the parsed command prelude of one receive-pack request.
// The reader remains positioned at the trailing pack stream.
type ReceivePackRequest struct {
	Commands     []ReceivePackCommand
	Capabilities map[string]bool
}

// ParseReceivePackCommands parses pkt-line receive-pack commands.
func ParseReceivePackCommands(r io.Reader) ([]ReceivePackCommand, error) {
	request, err := ParseReceivePackRequest(r)
	return request.Commands, err
}

// ParseReceivePackRequest parses pkt-line receive-pack commands and the
// capabilities attached to the first command.
func ParseReceivePackRequest(r io.Reader) (ReceivePackRequest, error) {
	request := ReceivePackRequest{Capabilities: map[string]bool{}}
	firstCommand := true
	for {
		payload, err := ReadPktLine(r)
		if errors.Is(err, ErrFlush) || errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return ReceivePackRequest{}, err
		}
		command, ok, err := parseCommandPayloadWithCapabilities(payload, firstCommand, request.Capabilities)
		if err != nil {
			return ReceivePackRequest{}, err
		}
		if ok {
			request.Commands = append(request.Commands, command)
			firstCommand = false
		}
	}
	return request, nil
}

func parseCommandPayloadWithCapabilities(payload []byte, first bool, capabilities map[string]bool) (ReceivePackCommand, bool, error) {
	payload = bytes.TrimSuffix(payload, []byte{'\n'})
	if index := bytes.IndexByte(payload, 0); index >= 0 {
		if first {
			for _, capability := range strings.Fields(string(payload[index+1:])) {
				capabilities[capability] = true
			}
		}
		payload = payload[:index]
	}
	line := string(payload)
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return ReceivePackCommand{}, false, nil
	}
	return parseCommandFields(parts, line)
}

func parseCommandFields(parts []string, line string) (ReceivePackCommand, bool, error) {
	if ok, err := parseShallow(parts, line); ok || err != nil {
		return ReceivePackCommand{}, false, err
	}
	if len(parts) != 3 {
		return ReceivePackCommand{}, false, fmt.Errorf("invalid receive-pack command %q", line)
	}
	if !isObjectID(parts[0]) || !isObjectID(parts[1]) {
		return ReceivePackCommand{}, false, fmt.Errorf("invalid receive-pack object id in command %q", line)
	}
	if len(parts[0]) != len(parts[1]) {
		return ReceivePackCommand{}, false, fmt.Errorf("mixed receive-pack object id lengths in command %q", line)
	}
	if !isValidRefName(parts[2]) {
		return ReceivePackCommand{}, false, fmt.Errorf("invalid receive-pack ref name in command %q", line)
	}
	command := ReceivePackCommand{Old: parts[0], New: parts[1], Ref: parts[2]}
	command.Kind = classify(command)
	return command, true, nil
}

func parseShallow(parts []string, line string) (bool, error) {
	if len(parts) == 2 && parts[0] == "shallow" {
		if !isObjectID(parts[1]) {
			return false, fmt.Errorf("invalid receive-pack shallow object id in command %q", line)
		}
		return true, nil
	}
	return false, nil
}

func classify(command ReceivePackCommand) RefUpdateKind {
	if isZeroObjectID(command.New) {
		return RefUpdateRefDelete
	}
	if strings.HasPrefix(command.Ref, "refs/tags/") {
		return classifyTag(command)
	}
	if strings.HasPrefix(command.Ref, "refs/heads/") {
		return classifyBranch(command)
	}
	return RefUpdateOther
}

func classifyTag(command ReceivePackCommand) RefUpdateKind {
	return classifyCreateOrUpdate(command, RefUpdateTagCreate, RefUpdateTagUpdate)
}

func classifyBranch(command ReceivePackCommand) RefUpdateKind {
	return classifyCreateOrUpdate(command, RefUpdateBranchCreate, RefUpdateBranchUpdate)
}

func classifyCreateOrUpdate(command ReceivePackCommand, create RefUpdateKind, update RefUpdateKind) RefUpdateKind {
	if isZeroObjectID(command.Old) {
		return create
	}
	return update
}

func isZeroObjectID(value string) bool {
	if !isObjectID(value) {
		return false
	}
	for _, char := range value {
		if char != '0' {
			return false
		}
	}
	return true
}

func isObjectID(value string) bool {
	if len(value) != sha1ObjectIDLength && len(value) != sha256ObjectIDLength {
		return false
	}
	for _, char := range value {
		if !isHex(char) {
			return false
		}
	}
	return true
}

func isHex(char rune) bool {
	return (char >= '0' && char <= '9') ||
		(char >= 'a' && char <= 'f') ||
		(char >= 'A' && char <= 'F')
}

func isValidRefName(ref string) bool {
	return hasValidRefShape(ref) && hasValidRefComponents(ref) && hasValidRefChars(ref)
}

func hasValidRefShape(ref string) bool {
	return strings.HasPrefix(ref, "refs/") &&
		ref != "refs/" &&
		ref != "@" &&
		!strings.Contains(ref, "..") &&
		!strings.Contains(ref, "@{") &&
		!strings.HasSuffix(ref, "/") &&
		!strings.HasSuffix(ref, ".")
}

func hasValidRefComponents(ref string) bool {
	for _, component := range strings.Split(ref, "/") {
		if component == "" || strings.HasPrefix(component, ".") || strings.HasSuffix(component, ".lock") {
			return false
		}
	}
	return true
}

func hasValidRefChars(ref string) bool {
	for _, char := range ref {
		if char <= ' ' || char == 0x7f || strings.ContainsRune("~^:?*[\\", char) {
			return false
		}
	}
	return true
}
