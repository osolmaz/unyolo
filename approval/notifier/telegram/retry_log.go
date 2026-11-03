package telegram

import (
	"log/slog"
	"time"
)

// retryLogInterval is the shortest time between two log lines for the
// failures of one retry loop.
const retryLogInterval = time.Minute

// retryLog reports the failures of one retry loop without flooding the log:
// it logs the first failure, then at most one failure a minute, and then the
// recovery.
type retryLog struct {
	logger   *slog.Logger
	loop     string
	now      func() time.Time
	failures int
	logged   time.Time
}

func newRetryLog(logger *slog.Logger, loop string) *retryLog {
	if logger == nil {
		logger = slog.Default()
	}
	return &retryLog{logger: logger, loop: loop, now: time.Now}
}

func (r *retryLog) failed(err error) {
	r.failures++
	now := r.now()
	if r.failures > 1 && now.Sub(r.logged) < retryLogInterval {
		return
	}
	r.logged = now
	r.logger.Warn("telegram "+r.loop+" failed; retrying", "error", err.Error(), "failures", r.failures)
}

func (r *retryLog) recovered() {
	if r.failures == 0 {
		return
	}
	r.logger.Info("telegram "+r.loop+" recovered", "failures", r.failures)
	r.failures = 0
}
