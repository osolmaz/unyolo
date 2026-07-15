// Package isolation checks whether a local agent identity is isolated from
// hf-broker's upstream credential on the broker host.
package isolation

import (
	"time"

	bkdoctor "github.com/osolmaz/brokerkit/doctor"
)

// Status is the overall isolation verdict.
type Status = bkdoctor.Status

const (
	StatusOK           = bkdoctor.StatusOK
	StatusUnsafe       = bkdoctor.StatusUnsafe
	StatusInconclusive = bkdoctor.StatusInconclusive
)

// CheckStatus is the result for one isolation check.
type CheckStatus = bkdoctor.CheckStatus

const (
	CheckPass    = bkdoctor.CheckPass
	CheckFail    = bkdoctor.CheckFail
	CheckWarn    = bkdoctor.CheckWarn
	CheckUnknown = bkdoctor.CheckUnknown
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
	Status      Status                      `json:"status"`
	Agent       AgentInfo                   `json:"agent"`
	Checks      []Check                     `json:"checks"`
	Credentials []bkdoctor.CredentialStatus `json:"credentials,omitempty"`
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
type Check = bkdoctor.Check

// ProbeResult is emitted by the active probe helper.
type ProbeResult = bkdoctor.ProbeResult

func credentialStatuses(opts Options) []bkdoctor.CredentialStatus {
	now := time.Now().UTC()
	values := make([]bkdoctor.CredentialStatus, 0, 4)
	for _, value := range []struct {
		class, path, revocation string
	}{
		{"huggingface-access", opts.TokenFile, bkdoctor.CredentialRevocationManual},
		{"broker-client", opts.ClientSecretsFile, bkdoctor.CredentialRevocationLocal},
		{"broker-operator", opts.OperatorSecretsFile, bkdoctor.CredentialRevocationLocal},
		{"telegram-bot", opts.TelegramTokenFile, bkdoctor.CredentialRevocationManual},
	} {
		if value.path != "" {
			values = append(values, bkdoctor.CredentialFileStatus(value.class, value.path, now,
				bkdoctor.DefaultCredentialRotationAge, time.Time{}, value.revocation))
		}
	}
	return bkdoctor.NormalizeCredentialStatuses(values)
}
