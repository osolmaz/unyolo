package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	corepolicy "github.com/osolmaz/brokerkit/policy"
)

func IsOperation(value string) bool {
	if descriptor, found := opcatalog.ByName(value); found && descriptor.AgentFacing {
		return true
	}
	switch Operation(value) {
	case OperationGitFetch, OperationGitPushAdvertise, OperationGitPushBranchCreate, OperationGitPushFastForward,
		OperationGitPushForce, OperationGitRefDelete, OperationGitTagUpdate, OperationWebhookGitHubReceive:
		return true
	default:
		return false
	}
}

type Effect string

const (
	EffectAllow   Effect = "allow"
	EffectDeny    Effect = "deny"
	EffectRequest Effect = "request"
	EffectNoMatch Effect = "no_match"
)

type Operation string

const (
	OperationGitFetch             Operation = "git.fetch"
	OperationGitPushAdvertise     Operation = "git.push.advertise"
	OperationGitPushBranchCreate  Operation = "git.push.branch_create"
	OperationGitPushFastForward   Operation = "git.push.fast_forward"
	OperationGitPushForce         Operation = "git.push.force"
	OperationGitRefDelete         Operation = "git.ref.delete"
	OperationGitTagUpdate         Operation = "git.tag.update"
	OperationWebhookGitHubReceive Operation = "webhook.github.receive"
)

type Target struct {
	Kind   string `json:"kind"`
	ID     int64  `json:"id,omitempty"`
	NodeID string `json:"node_id,omitempty"`
	Owner  string `json:"owner,omitempty"`
	Repo   string `json:"repo,omitempty"`
	Name   string `json:"name,omitempty"`
	Number int64  `json:"number,omitempty"`
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

type scopeFile struct {
	Rules *[]Rule `json:"rules"`
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
	return Parse(data)
}

// Parse strictly decodes and validates one GitHub scope policy.
func Parse(data []byte) (*Policy, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var raw scopeFile
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse scope policy: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err == nil {
		return nil, errors.New("parse scope policy: trailing json data")
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse scope policy: %w", err)
	}
	if raw.Rules == nil {
		return nil, errors.New("parse scope policy: rules is required")
	}
	return New(Scope{Rules: *raw.Rules})
}

func New(scope Scope) (*Policy, error) {
	data, err := corePolicyJSON(scope)
	if err != nil {
		return nil, err
	}
	registry, err := CatalogRegistry()
	if err != nil {
		return nil, err
	}
	core, err := corepolicy.Parse(data, registry)
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

func AuthorizationRegistry() (corepolicy.Registry, error) { return CatalogRegistry() }

// AuthorizationRequest projects generated GitHub adapter metadata into the
// shared policy model.
func AuthorizationRequest(client, operation, targetKind string, targetFields, attrs map[string][]string) corepolicy.Request {
	return corepolicy.Request{
		Client:    strings.TrimSpace(client),
		Operation: strings.TrimSpace(operation),
		Target: corepolicy.Target{
			Kind:   strings.TrimSpace(targetKind),
			Fields: targetFields,
		},
		Attrs: attrs,
	}
}

func (p *Policy) DecideAuthorization(request corepolicy.Request, options corepolicy.DecisionOptions) corepolicy.Decision {
	if p == nil || p.core == nil {
		return corepolicy.Decision{Effect: corepolicy.EffectNoMatch, Reason: "policy is unavailable"}
	}
	return p.core.Decide(request, options)
}

func (p *Policy) AuthorizationDecision(decision corepolicy.Decision) Decision {
	return fromCoreDecision(decision)
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
	if request.Target.Kind == "repo" {
		return request.Target.Owner == "" || request.Target.Name == ""
	}
	if request.Target.Kind == "installation" {
		return false
	}
	return !targetHasIdentity(request.Target)
}

func targetHasIdentity(target Target) bool {
	if target.ID > 0 || strings.TrimSpace(target.NodeID) != "" {
		return true
	}
	return strings.TrimSpace(target.Name) != "" || strings.TrimSpace(target.Owner) != "" || strings.TrimSpace(target.Repo) != "" || target.Number > 0
}

// mutate4go-manifest-begin
// {"version":1,"tested_at":"2026-07-10T06:09:38+08:00","module_hash":"aae030be0715bc675d6c13bb72ffb351d53e381947e7a8538130fa547dc188db","functions":[{"id":"func/LoadFile","name":"LoadFile","line":86,"end_line":108,"hash":"7629b958d391e28549c126632c2697060a12e9ae3f9a81f4f0ce8421e25823f1"},{"id":"func/New","name":"New","line":110,"end_line":120,"hash":"07ab226979cbc416c37054fcd313ec566f90795c6461293691f15d54681b74e5"},{"id":"func/Policy.Evaluate","name":"Policy.Evaluate","line":122,"end_line":124,"hash":"7f06074ef61e81654643ff53781a019aae51386534cacb8f6650161c4f6a1689"},{"id":"func/Policy.EvaluateGrantRequest","name":"Policy.EvaluateGrantRequest","line":126,"end_line":128,"hash":"4d911af78e46b4ac6fda5b344c8da01721bc61d2a66f208d62a99dbf41ee608a"},{"id":"func/Policy.evaluate","name":"Policy.evaluate","line":130,"end_line":137,"hash":"323f2780291d85d67fdcf73aa832e185f1271f1d47b9936b8c4591978fce234d"},{"id":"func/Policy.Allows","name":"Policy.Allows","line":139,"end_line":141,"hash":"a43075cda047810dd1c13616ae8d4258ba4f4324459f465193d7a4860ab3252e"},{"id":"func/CoreTarget","name":"CoreTarget","line":143,"end_line":148,"hash":"430b5e52dc1ef176e1a9626d751310c3ebe6849259d7754c261e90a824f70ca4"},{"id":"func/incompleteRequest","name":"incompleteRequest","line":150,"end_line":155,"hash":"f7ea8eefc87286081a534447cf06e5eea08725bb764f9bad65ca511b6356ad97"}]}
// mutate4go-manifest-end
