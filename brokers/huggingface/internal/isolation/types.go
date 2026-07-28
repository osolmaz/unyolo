// Package isolation checks whether a local agent identity is isolated from
// hf-broker's upstream credential on the broker host.
package isolation

import (
	"time"

	unyolodoctor "github.com/osolmaz/unyolo/internal/host/doctor"
)

// Status is the overall isolation verdict.
type Status = unyolodoctor.Status

const (
	StatusOK           = unyolodoctor.StatusOK
	StatusUnsafe       = unyolodoctor.StatusUnsafe
	StatusInconclusive = unyolodoctor.StatusInconclusive
)

// CheckStatus is the result for one isolation check.
type CheckStatus = unyolodoctor.CheckStatus

const (
	CheckPass    = unyolodoctor.CheckPass
	CheckFail    = unyolodoctor.CheckFail
	CheckWarn    = unyolodoctor.CheckWarn
	CheckUnknown = unyolodoctor.CheckUnknown
)

// Options controls an isolation check run.
type Options struct {
	AgentUser           string
	AgentUID            int
	AgentUIDSet         bool
	AgentPID            int
	BrokerPID           int
	TokenFile           string
	ClientSecretsFile   string
	OperatorSecretsFile string
	TelegramTokenFile   string
	Socket              string

	HelperPath string
}

// Report is the machine-readable output for doctor isolation.
type Report struct {
	Status      Status                          `json:"status"`
	Agent       AgentInfo                       `json:"agent"`
	Checks      []Check                         `json:"checks"`
	Credentials []unyolodoctor.CredentialStatus `json:"credentials,omitempty"`
}

// AgentInfo identifies the checked agent identity.
type AgentInfo struct {
	User   string   `json:"user,omitempty"`
	UID    int      `json:"uid"`
	GID    int      `json:"gid,omitempty"`
	GIDs   []int    `json:"gids,omitempty"`
	Groups []string `json:"groups,omitempty"`
	PID    int      `json:"pid,omitempty"`
}

// Check is one stable doctor finding.
type Check = unyolodoctor.Check

// ProbeResult is emitted by the active probe helper.
type ProbeResult = unyolodoctor.ProbeResult

func credentialStatuses(opts Options) []unyolodoctor.CredentialStatus {
	now := time.Now().UTC()
	values := make([]unyolodoctor.CredentialStatus, 0, 4)
	for _, value := range []struct {
		class, path, revocation string
	}{
		{"huggingface-access", opts.TokenFile, unyolodoctor.CredentialRevocationManual},
		{"broker-client", opts.ClientSecretsFile, unyolodoctor.CredentialRevocationLocal},
		{"broker-operator", opts.OperatorSecretsFile, unyolodoctor.CredentialRevocationLocal},
		{"telegram-bot", opts.TelegramTokenFile, unyolodoctor.CredentialRevocationManual},
	} {
		if value.path != "" {
			values = append(values, unyolodoctor.CredentialFileStatus(value.class, value.path, now,
				unyolodoctor.DefaultCredentialRotationAge, time.Time{}, value.revocation))
		}
	}
	return unyolodoctor.NormalizeCredentialStatuses(values)
}
