package providercredential

import (
	"errors"
	"sync/atomic"
	"time"
)

// Service owns the active immutable credential snapshot.
type Service struct{ snapshot atomic.Pointer[Snapshot] }

func NewService(initial Snapshot) (*Service, error) {
	normalized, err := Normalize(initial)
	if err != nil {
		return nil, err
	}
	service := &Service{}
	service.snapshot.Store(&normalized)
	return service, nil
}

func (s *Service) Snapshot() (Snapshot, error) {
	if s == nil || s.snapshot.Load() == nil {
		return Snapshot{}, errors.New("provider credential snapshot is unavailable")
	}
	value := *s.snapshot.Load()
	value.Capabilities = append([]Capability(nil), value.Capabilities...)
	return value, nil
}

func (s *Service) Replace(next Snapshot) error {
	normalized, err := Normalize(next)
	if err != nil {
		return err
	}
	current, err := s.Snapshot()
	if err == nil && normalized.Generation <= current.Generation {
		return errors.New("provider credential generation must increase")
	}
	s.snapshot.Store(&normalized)
	return nil
}

func (s *Service) Evaluate(requirement Requirement, target Target) Evaluation {
	snapshot, err := s.Snapshot()
	if err != nil {
		return Evaluation{Allowed: false, Missing: []string{"credential.valid"}}
	}
	return Evaluate(snapshot, requirement, target)
}

func (s *Service) CanSatisfy(requirement Requirement, now time.Time) bool {
	snapshot, err := s.Snapshot()
	return err == nil && CanSatisfy(snapshot, requirement, now)
}

func (s *Service) Binding() (Binding, error) {
	snapshot, err := s.Snapshot()
	if err != nil {
		return Binding{}, err
	}
	return Bind(snapshot), nil
}

func (s *Service) Validate(binding Binding) error {
	snapshot, err := s.Snapshot()
	if err != nil {
		return err
	}
	return ValidateBinding(snapshot, binding)
}
