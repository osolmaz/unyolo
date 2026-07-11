// Package audit emits one structured log line per broker request.
//
// Entries never carry secrets, request bodies, or pack contents; callers
// must only pass identifiers, decisions, and refusal reasons.
package audit

import (
	"io"
	"log/slog"
)

// Decision values recorded per request.
const (
	DecisionAllowed   = "allowed"
	DecisionRefused   = "refused"
	DecisionGrantUsed = "grant-used"
)

// Entry is one audit record.
type Entry struct {
	Client                string   // resolved client name, or "" before authentication
	Operation             string   // operation class, e.g. "git.push.force"
	Target                string   // e.g. "dataset/osolmaz/scraped-news"
	Decision              string   // DecisionAllowed or DecisionRefused
	Reason                string   // refusal reason, empty when allowed
	UpstreamStatus        int      // HTTP status from upstream, 0 if never contacted
	MatchedDenyRuleIDs    []string // policy deny rules that matched this request
	MatchedGrantRuleIDs   []string // generated grant rules that matched this request
	MatchedAllowRuleIDs   []string // policy allow rules that matched this request
	MatchedRequestRuleIDs []string // policy request rules that matched this request
	GrantID               string   // generated grant id when policy allowed through a grant
	PlanDigest            string   // private immutable-plan correlation; never exposed to clients
}

// Logger writes audit entries as JSON lines.
type Logger struct {
	logger *slog.Logger
}

// New returns a Logger writing JSON audit lines to w.
func New(w io.Writer) *Logger {
	return &Logger{logger: slog.New(slog.NewJSONHandler(w, nil))}
}

// Record emits one audit line.
func (l *Logger) Record(e Entry) {
	l.logger.Info("request",
		"client", e.Client,
		"operation", e.Operation,
		"target", e.Target,
		"decision", e.Decision,
		"reason", e.Reason,
		"upstream_status", e.UpstreamStatus,
		"matched_deny_rule_ids", nonNilStrings(e.MatchedDenyRuleIDs),
		"matched_grant_rule_ids", nonNilStrings(e.MatchedGrantRuleIDs),
		"matched_allow_rule_ids", nonNilStrings(e.MatchedAllowRuleIDs),
		"matched_request_rule_ids", nonNilStrings(e.MatchedRequestRuleIDs),
		"grant_id", e.GrantID,
		"plan_digest", e.PlanDigest,
	)
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
