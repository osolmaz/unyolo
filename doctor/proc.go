package doctor

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

var rootEquivalentCapabilities = map[int]string{
	0: "CAP_CHOWN", 1: "CAP_DAC_OVERRIDE", 2: "CAP_DAC_READ_SEARCH",
	3: "CAP_FOWNER", 4: "CAP_FSETID", 6: "CAP_SETGID", 7: "CAP_SETUID",
	16: "CAP_SYS_MODULE", 17: "CAP_SYS_RAWIO", 19: "CAP_SYS_PTRACE",
	21: "CAP_SYS_ADMIN", 31: "CAP_SETFCAP",
}

// ProcessStatus contains the Linux process credentials and capabilities used
// by host-isolation checks.
type ProcessStatus struct {
	FilesystemUID int
	FilesystemGID int
	UIDs          []int
	GIDs          []int
	Groups        []int
	EffectiveCaps uint64
	PermittedCaps uint64
}

// AllUIDsMatch reports whether every real, effective, saved, and filesystem
// process UID equals uid.
func (s ProcessStatus) AllUIDsMatch(uid int) bool {
	return allProcessIDsMatch(s.UIDs, uid)
}

// HasUID reports whether any process UID equals uid.
func (s ProcessStatus) HasUID(uid int) bool {
	for _, value := range s.UIDs {
		if value == uid {
			return true
		}
	}
	return false
}

// RootEquivalentCapabilityNames returns dangerous Linux capability names set
// in effective or permitted.
func RootEquivalentCapabilityNames(effective, permitted uint64) []string {
	bits := effective | permitted
	var names []string
	for bit, name := range rootEquivalentCapabilities {
		if bits&(uint64(1)<<bit) != 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func allProcessIDsMatch(values []int, want int) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		if value != want {
			return false
		}
	}
	return true
}

// ParseProcessStatus parses the relevant fields from Linux /proc/PID/status.
func ParseProcessStatus(data []byte) (ProcessStatus, error) {
	var parser processStatusParser
	for _, line := range strings.Split(string(data), "\n") {
		if err := parser.consume(line); err != nil {
			return ProcessStatus{}, err
		}
	}
	return parser.finish()
}

type processStatusParser struct {
	status ProcessStatus
	uidSet bool
	gidSet bool
}

func (p *processStatusParser) consume(line string) error {
	key, value, ok := strings.Cut(line, ":")
	if !ok {
		return nil
	}
	value = strings.TrimSpace(value)
	switch key {
	case "Uid", "Gid":
		return p.consumeIDs(key, value)
	case "Groups":
		return p.consumeGroups(value)
	case "CapEff", "CapPrm":
		return p.consumeCapabilities(key, value)
	default:
		return nil
	}
}

func (p *processStatusParser) consumeIDs(key, value string) error {
	values, err := parseProcessInts(strings.ToLower(key), value)
	if err != nil {
		return err
	}
	if key == "Uid" {
		p.status.FilesystemUID, p.status.UIDs, p.uidSet = filesystemID(values), values, true
	} else {
		p.status.FilesystemGID, p.status.GIDs, p.gidSet = filesystemID(values), values, true
	}
	return nil
}

func (p *processStatusParser) consumeGroups(value string) error {
	if value == "" {
		p.status.Groups = nil
		return nil
	}
	groups, err := parseProcessInts("groups", value)
	p.status.Groups = groups
	return err
}

func (p *processStatusParser) consumeCapabilities(key, value string) error {
	capabilities, err := strconv.ParseUint(value, 16, 64)
	if err != nil {
		return fmt.Errorf("parse %s: %w", key, err)
	}
	if key == "CapEff" {
		p.status.EffectiveCaps = capabilities
	} else {
		p.status.PermittedCaps = capabilities
	}
	return nil
}

func (p processStatusParser) finish() (ProcessStatus, error) {
	if !p.uidSet {
		return ProcessStatus{}, errors.New("uid field is missing")
	}
	if !p.gidSet {
		return ProcessStatus{}, errors.New("gid field is missing")
	}
	return p.status, nil
}

func parseProcessInts(name, value string) ([]int, error) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return nil, fmt.Errorf("%s field is empty", name)
	}
	values := make([]int, 0, len(fields))
	for _, field := range fields {
		parsed, err := strconv.Atoi(field)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		values = append(values, parsed)
	}
	return values, nil
}

func filesystemID(values []int) int {
	if len(values) >= 4 {
		return values[3]
	}
	return values[0]
}
