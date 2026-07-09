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
