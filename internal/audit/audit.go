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
	Client         string // resolved client name, or "" before authentication
	Operation      string // operation class, e.g. "git_history_rewrite"
	Target         string // e.g. "dataset/osolmaz/scraped-news"
	Decision       string // DecisionAllowed or DecisionRefused
	Reason         string // refusal reason, empty when allowed
	UpstreamStatus int    // HTTP status from upstream, 0 if never contacted
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
	)
}
