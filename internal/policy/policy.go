package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	corepolicy "github.com/osolmaz/brokerkit/policy"
)

type Effect string

const (
	EffectAllow   Effect = "allow"
	EffectDeny    Effect = "deny"
	EffectRequest Effect = "request"
	EffectNoMatch Effect = "no_match"
)

type Operation string

const (
	OperationGitFetch              Operation = "git.fetch"
	OperationGitPushAdvertise      Operation = "git.push.advertise"
	OperationGitPushBranchCreate   Operation = "git.push.branch_create"
	OperationGitPushFastForward    Operation = "git.push.fast_forward"
	OperationGitPushForce          Operation = "git.push.force"
	OperationGitRefDelete          Operation = "git.ref.delete"
	OperationGitTagUpdate          Operation = "git.tag.update"
	OperationPullRequestCreate     Operation = "pr.create"
	OperationPullRequestUpdate     Operation = "pr.update"
	OperationPullRequestMerge      Operation = "pr.merge"
	OperationChecksRead            Operation = "checks.read"
	OperationRepoMetadataRead      Operation = "repo.metadata.read"
	OperationContentsRead          Operation = "contents.read"
	OperationInstallationReposList Operation = "installation.repos.list"
	OperationWebhookGitHubReceive  Operation = "webhook.github.receive"
)

type Target struct {
	Kind  string `json:"kind"`
	Owner string `json:"owner,omitempty"`
	Name  string `json:"name,omitempty"`
}

type Rule struct {
	ID         string              `json:"id"`
	Effect     Effect              `json:"effect"`
	Clients    []string            `json:"clients"`
	Operations []Operation         `json:"operations"`
	Targets    []Target            `json:"targets"`
	Attrs      map[string][]string `json:"attrs,omitempty"`
}

type Scope struct {
	Rules []Rule `json:"rules"`
}

type Request struct {
	Client    string
	Operation Operation
	Target    Target
	Attrs     map[string]string
}

type Decision struct {
	Effect         Effect
	Allowed        bool
	Reason         string
	MatchedRuleIDs []string
	GrantID        string
	GrantPolicy    *corepolicy.GrantPolicy
}

type Policy struct {
	core *corepolicy.Policy
}

func LoadFile(file string) (*Policy, error) {
	// #nosec G304 -- policy file is an operator-managed config path, not request input.
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read scope file: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var scope Scope
	if err := decoder.Decode(&scope); err != nil {
		return nil, fmt.Errorf("parse scope file: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err == nil {
		return nil, errors.New("parse scope file: trailing json data")
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse scope file: %w", err)
	}
	return New(scope)
}

func New(scope Scope) (*Policy, error) {
	data, err := corePolicyJSON(scope)
	if err != nil {
		return nil, err
	}
	core, err := corepolicy.Parse(data, registry())
	if err != nil {
		return nil, err
	}
	return &Policy{core: core}, nil
}

func (p *Policy) Evaluate(request Request, activeGrants ...corepolicy.Grant) Decision {
	return p.evaluate(request, corepolicy.DecisionOptions{ActiveGrants: activeGrants})
}

func (p *Policy) EvaluateGrantRequest(request Request) Decision {
	return p.evaluate(request, corepolicy.DecisionOptions{ForGrantRequest: true})
}

func (p *Policy) evaluate(request Request, opts corepolicy.DecisionOptions) Decision {
	request = normalizeRequest(request)
	if incompleteRequest(request) {
		return Decision{Effect: EffectNoMatch, Reason: "request is incomplete"}
	}
	decision := p.core.Decide(coreRequest(request), opts)
	return fromCoreDecision(decision)
}

func (p *Policy) Allows(request Request) bool {
	return p.Evaluate(request).Allowed
}

func CoreTarget(target Target) corepolicy.Target {
	return corepolicy.Target{
		Kind:   target.Kind,
		Fields: targetFields(target),
	}
}

func incompleteRequest(request Request) bool {
	if request.Client == "" || request.Operation == "" || request.Target.Kind == "" {
		return true
	}
	return request.Target.Kind == "repo" && (request.Target.Owner == "" || request.Target.Name == "")
}

// mutate4go-manifest-begin
// {"version":1,"tested_at":"2026-07-09T22:59:11+08:00","module_hash":"2abf421be0292da21a97addc093cb7d36599b594d5d134c68b0fae0d87895b69","functions":[{"id":"func/LoadFile","name":"LoadFile","line":82,"end_line":101,"hash":"60bcdba03d22ae5ab20ad1b0ebe5891258343feb8247231f96abb57c01393ac8"},{"id":"func/New","name":"New","line":103,"end_line":113,"hash":"07ab226979cbc416c37054fcd313ec566f90795c6461293691f15d54681b74e5"},{"id":"func/Policy.Evaluate","name":"Policy.Evaluate","line":115,"end_line":117,"hash":"7f06074ef61e81654643ff53781a019aae51386534cacb8f6650161c4f6a1689"},{"id":"func/Policy.EvaluateGrantRequest","name":"Policy.EvaluateGrantRequest","line":119,"end_line":121,"hash":"4d911af78e46b4ac6fda5b344c8da01721bc61d2a66f208d62a99dbf41ee608a"},{"id":"func/Policy.evaluate","name":"Policy.evaluate","line":123,"end_line":130,"hash":"323f2780291d85d67fdcf73aa832e185f1271f1d47b9936b8c4591978fce234d"},{"id":"func/Policy.Allows","name":"Policy.Allows","line":132,"end_line":134,"hash":"a43075cda047810dd1c13616ae8d4258ba4f4324459f465193d7a4860ab3252e"},{"id":"func/CoreTarget","name":"CoreTarget","line":136,"end_line":141,"hash":"430b5e52dc1ef176e1a9626d751310c3ebe6849259d7754c261e90a824f70ca4"},{"id":"func/incompleteRequest","name":"incompleteRequest","line":143,"end_line":148,"hash":"f7ea8eefc87286081a534447cf06e5eea08725bb764f9bad65ca511b6356ad97"}]}
// mutate4go-manifest-end
