// Package audit writes secret-safe structured broker audit events.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/osolmaz/brokerkit/internal/copyx"
)

// Event is one broker audit event.
type Event struct {
	Time           time.Time         `json:"time"`
	Broker         string            `json:"broker"`
	Client         string            `json:"client,omitempty"`
	Operation      string            `json:"operation,omitempty"`
	Target         string            `json:"target,omitempty"`
	Attrs          map[string]string `json:"attrs,omitempty"`
	Decision       string            `json:"decision,omitempty"`
	Reason         string            `json:"reason,omitempty"`
	MatchedRuleIDs []string          `json:"matched_rule_ids,omitempty"`
	GrantID        string            `json:"grant_id,omitempty"`
	Approver       string            `json:"approver,omitempty"`
	Status         int               `json:"status,omitempty"`
	ErrorCode      string            `json:"error_code,omitempty"`
	Extensions     map[string]string `json:"extensions,omitempty"`
}

// Writer writes audit events as JSON lines.
type Writer struct {
	mu  sync.Mutex
	out io.Writer
	now func() time.Time
}

// New returns an audit Writer.
func New(out io.Writer) *Writer {
	return &Writer{out: out, now: time.Now}
}

// WithClock sets the clock used for events with no Time.
func (w *Writer) WithClock(now func() time.Time) *Writer {
	if now != nil {
		w.now = now
	}
	return w
}

// Record writes one audit event.
func (w *Writer) Record(event Event) error {
	if event.Time.IsZero() {
		event.Time = w.now().UTC()
	}
	event.Attrs = secretSafeMap(event.Attrs)
	event.Extensions = secretSafeMap(event.Extensions)
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode audit event: %w", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.out.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write audit event: %w", err)
	}
	return nil
}

func secretSafeMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := copyx.StringMap(values)
	for key := range out {
		if isSensitiveField(key) {
			delete(out, key)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func isSensitiveField(key string) bool {
	normalized := strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(key))
	for _, marker := range []string{"authorization", "password", "credential", "privatekey", "apikey", "accesskey", "secret", "token", "cookie"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}
