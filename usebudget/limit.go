// Package usebudget models finite and unlimited approval use budgets.
package usebudget

import (
	"bytes"
	"encoding/json"
	"errors"
)

// Limit is either a positive finite use count or Unlimited.
type Limit int

// Unlimited represents a grant that remains usable until its time limit.
const Unlimited Limit = 0

// IsUnlimited reports whether the limit has no use-count ceiling.
func (l Limit) IsUnlimited() bool { return l == Unlimited }

// IsFinite reports whether the limit is a positive finite count.
func (l Limit) IsFinite() bool { return l > Unlimited }

// Allows reports whether used and reserved uses remain within the limit.
func (l Limit) Allows(used, reserved int) bool {
	return l.IsUnlimited() || used+reserved < int(l)
}

// Exhausted reports whether a finite limit has been consumed.
func (l Limit) Exhausted(used int) bool {
	return l.IsFinite() && used >= int(l)
}

// Remaining returns the finite remaining count and whether the limit is finite.
func (l Limit) Remaining(used, reserved int) (int, bool) {
	if l.IsUnlimited() {
		return 0, false
	}
	return max(int(l)-used-reserved, 0), true
}

// MarshalJSON represents unlimited budgets as JSON null.
func (l Limit) MarshalJSON() ([]byte, error) {
	if l.IsUnlimited() {
		return []byte("null"), nil
	}
	return json.Marshal(int(l))
}

// UnmarshalJSON accepts JSON null or a positive integer.
func (l *Limit) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		*l = Unlimited
		return nil
	}
	var value int
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	if value < 1 {
		return errors.New("use limit must be a positive integer or null")
	}
	*l = Limit(value)
	return nil
}

// Optional preserves whether a request omitted its use limit, explicitly
// requested unlimited use, or requested a finite count.
type Optional struct {
	Limit     Limit
	Specified bool
}

// Finite returns an explicitly requested finite use limit.
func Finite(value int) Optional { return Optional{Limit: Limit(value), Specified: true} }

// NoLimit returns an explicitly requested unlimited use budget.
func NoLimit() Optional { return Optional{Limit: Unlimited, Specified: true} }

// UnmarshalJSON marks the value as specified before decoding its limit.
func (o *Optional) UnmarshalJSON(data []byte) error {
	o.Specified = true
	return o.Limit.UnmarshalJSON(data)
}

// MarshalJSON delegates to the requested limit representation.
func (o Optional) MarshalJSON() ([]byte, error) { return o.Limit.MarshalJSON() }
