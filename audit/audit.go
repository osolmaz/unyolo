// Package audit writes secret-safe structured broker audit events.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/osolmaz/brokerkit/internal/slicex"
)

const (
	maxMetadataFields = 32
	maxMetadataKey    = 128
	maxMetadataValue  = 1024
)

// Decision values used by broker request audit events.
const (
	DecisionAllowed   = "allowed"
	DecisionRefused   = "refused"
	DecisionGrantUsed = "grant-used"
)

// Event is one broker audit event.
type Event struct {
	Time                  time.Time         `json:"time"`
	Broker                string            `json:"broker"`
	Client                string            `json:"client"`
	Operation             string            `json:"operation"`
	Target                string            `json:"target"`
	Attrs                 map[string]string `json:"attrs,omitempty"`
	Decision              string            `json:"decision"`
	Reason                string            `json:"reason"`
	MatchedRuleIDs        []string          `json:"matched_rule_ids,omitempty"`
	MatchedDenyRuleIDs    []string          `json:"matched_deny_rule_ids"`
	MatchedGrantRuleIDs   []string          `json:"matched_grant_rule_ids"`
	MatchedAllowRuleIDs   []string          `json:"matched_allow_rule_ids"`
	MatchedRequestRuleIDs []string          `json:"matched_request_rule_ids"`
	GrantID               string            `json:"grant_id"`
	PlanDigest            string            `json:"plan_digest"`
	Approver              string            `json:"approver,omitempty"`
	Status                int               `json:"status,omitempty"`
	UpstreamStatus        int               `json:"upstream_status"`
	ErrorCode             string            `json:"error_code,omitempty"`
	Extensions            map[string]string `json:"extensions,omitempty"`
}

// Recorder accepts one secret-safe audit event.
type Recorder interface {
	Record(Event) error
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
	event.MatchedDenyRuleIDs = slicex.NonNil(event.MatchedDenyRuleIDs)
	event.MatchedGrantRuleIDs = slicex.NonNil(event.MatchedGrantRuleIDs)
	event.MatchedAllowRuleIDs = slicex.NonNil(event.MatchedAllowRuleIDs)
	event.MatchedRequestRuleIDs = slicex.NonNil(event.MatchedRequestRuleIDs)
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
	keys := make([]string, 0, len(values))
	for key := range values {
		if safeMetadataKey(key) {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Strings(keys)
	if len(keys) > maxMetadataFields {
		keys = keys[:maxMetadataFields]
	}
	out := make(map[string]string, len(keys))
	for _, key := range keys {
		out[key] = boundedMetadataValue(values[key])
	}
	return out
}

func safeMetadataKey(key string) bool {
	return key != "" && len(key) <= maxMetadataKey && !isSensitiveField(key)
}

func boundedMetadataValue(value string) string {
	if len(value) > maxMetadataValue {
		value = value[:maxMetadataValue]
	}
	return strings.ToValidUTF8(value, "")
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
