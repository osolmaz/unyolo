// Package isolation checks whether a local agent identity is isolated from
// hf-broker's upstream credential on the broker host.
package isolation

// Status is the overall isolation verdict.
type Status string

const (
	StatusOK           Status = "ok"
	StatusUnsafe       Status = "unsafe"
	StatusInconclusive Status = "inconclusive"
)

// CheckStatus is the result for one isolation check.
type CheckStatus string

const (
	CheckPass    CheckStatus = "pass"
	CheckFail    CheckStatus = "fail"
	CheckWarn    CheckStatus = "warn"
	CheckUnknown CheckStatus = "unknown"
)

// Options controls an isolation check run.
type Options struct {
	AgentUser   string
	AgentUID    int
	AgentUIDSet bool
	AgentPID    int
	BrokerPID   int
	TokenFile   string
	Socket      string

	HelperPath string
}

// Report is the machine-readable output for doctor isolation.
type Report struct {
	Status Status    `json:"status"`
	Agent  AgentInfo `json:"agent"`
	Checks []Check   `json:"checks"`
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
type Check struct {
	Status  CheckStatus `json:"status"`
	Name    string      `json:"name"`
	Message string      `json:"message"`
}

// ProbeResult is emitted by the active probe helper.
type ProbeResult struct {
	TokenFileReadable bool `json:"token_file_readable"`
	TokenFileWritable bool `json:"token_file_writable"`
	BrokerEnvReadable bool `json:"broker_env_readable"`
	SocketConnectable bool `json:"socket_connectable"`
}
