package providercredential

import (
	"context"
	"errors"
)

const maxSecretBytes = 64 * 1024

// Secret owns a bounded candidate credential and supports explicit clearing.
type Secret struct{ value []byte }

func NewSecret(value []byte) (*Secret, error) {
	if len(value) == 0 || len(value) > maxSecretBytes {
		return nil, errors.New("provider credential input is empty or too large")
	}
	return &Secret{value: append([]byte(nil), value...)}, nil
}

func (s *Secret) Bytes() ([]byte, error) {
	if s == nil || len(s.value) == 0 {
		return nil, errors.New("provider credential input is unavailable")
	}
	return append([]byte(nil), s.value...), nil
}

func (s *Secret) Clear() {
	if s == nil {
		return
	}
	clear(s.value)
	s.value = nil
}

type Enrollment struct {
	URL          string `json:"url"`
	Instructions string `json:"instructions"`
}

type ProbeState string

const (
	ProbeValid        ProbeState = "valid"
	ProbeInvalid      ProbeState = "invalid"
	ProbeUnavailable  ProbeState = "unavailable"
	ProbeInconclusive ProbeState = "inconclusive"
)

type ProbeResult struct {
	State      ProbeState `json:"state"`
	Diagnostic string     `json:"diagnostic,omitempty"`
}

// Adapter is the provider-specific portion of the shared credential lifecycle.
type Adapter interface {
	Provider() string
	Enrollment(context.Context) (Enrollment, error)
	Inspect(context.Context, *Secret) (Snapshot, error)
	Requirement(operation string) (Requirement, bool)
	Probe(context.Context, Snapshot) (ProbeResult, error)
}
