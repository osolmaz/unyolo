package apicompat

import (
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/osolmaz/unyolo/brokers/github/internal/opbinding"
	"github.com/osolmaz/unyolo/brokers/github/internal/opcatalog"
	"github.com/osolmaz/unyolo/brokers/github/internal/operations"
	"github.com/osolmaz/unyolo/brokers/github/internal/policy"
	"github.com/osolmaz/unyolo/internal/strictjson"
	"github.com/osolmaz/unyolo/operation/capability"
)

// spanningParameters may contain "/" when they are the last template segment,
// as GitHub accepts for file paths, refs, branches, and compare ranges.
var spanningParameters = []string{"basehead", "branch", "path", "ref"}

// RESTMatch is one REST request path matched to exactly one catalog binding.
type RESTMatch struct {
	Binding    opbinding.Binding
	Descriptor opcatalog.Descriptor
	// Path is the escaped upstream path, relative to the GitHub API root.
	Path   string
	values map[string]string
}

type restTemplate struct {
	binding  opbinding.Binding
	segments []string
}

var restIndex = sync.OnceValues(loadRESTIndex)

func loadRESTIndex() (map[string][]restTemplate, error) {
	bindings, err := opbinding.All()
	if err != nil {
		return nil, err
	}
	index := map[string][]restTemplate{}
	for _, binding := range bindings {
		if binding.ServerRole != "api" {
			continue
		}
		segments := strings.Split(strings.TrimPrefix(binding.PathTemplate, "/"), "/")
		index[binding.Method] = append(index[binding.Method], restTemplate{binding: binding, segments: segments})
	}
	return index, nil
}

// MatchREST matches one method and escaped path, without the /api/v3 prefix,
// to the most specific reviewed REST binding and checks that the broker may
// serve its operation through the GitHub-compatible API.
func MatchREST(method, escapedPath string) (RESTMatch, error) {
	segments, err := pathSegments(escapedPath)
	if err != nil {
		return RESTMatch{}, err
	}
	index, err := restIndex()
	if err != nil {
		return RESTMatch{}, refuse(http.StatusInternalServerError, "gh-broker: REST bindings are unavailable")
	}
	templates, values, err := bestTemplates(index[method], segments)
	if err != nil {
		return RESTMatch{}, err
	}
	if len(templates) != 1 {
		return RESTMatch{}, unsupported("%s %s maps to more than one operation", method, templates[0].binding.PathTemplate)
	}
	descriptor, err := servableDescriptor(templates[0].binding.Operation)
	if err != nil {
		return RESTMatch{}, err
	}
	return RESTMatch{Binding: templates[0].binding, Descriptor: descriptor, Path: "/" + strings.Join(segments, "/"), values: values}, nil
}

func pathSegments(escapedPath string) ([]string, error) {
	trimmed := strings.TrimPrefix(escapedPath, "/")
	if trimmed == "" || trimmed == escapedPath {
		return nil, refuse(http.StatusNotFound, "Not Found")
	}
	segments := strings.Split(trimmed, "/")
	for _, segment := range segments {
		value, err := url.PathUnescape(segment)
		if err != nil || value == "" || value == "." || value == ".." || strings.Contains(value, "/") {
			return nil, malformed("the request path contains an unsupported segment")
		}
	}
	return segments, nil
}

// bestTemplates returns the templates with the most literal segments among
// exact-length matches, or among spanning matches when none matches exactly.
func bestTemplates(candidates []restTemplate, segments []string) ([]restTemplate, map[string]string, error) {
	for _, spanning := range []bool{false, true} {
		best, bestScore, values := []restTemplate(nil), -1, map[string]string(nil)
		for _, candidate := range candidates {
			score, matched, ok := matchTemplate(candidate.segments, segments, spanning)
			switch {
			case !ok || score < bestScore:
			case score > bestScore:
				best, bestScore, values = []restTemplate{candidate}, score, matched
			default:
				best = append(best, candidate)
			}
		}
		if len(best) > 0 {
			return best, values, nil
		}
	}
	return nil, nil, refuse(http.StatusNotFound, "Not Found")
}

func matchTemplate(template, segments []string, spanning bool) (int, map[string]string, bool) {
	if !lengthMatches(template, segments, spanning) {
		return 0, nil, false
	}
	score, values := 0, map[string]string{}
	for index, part := range template {
		name, isParameter := templateParameter(part)
		if !isParameter {
			if part != segments[index] {
				return 0, nil, false
			}
			score++
			continue
		}
		raw := segments[index]
		if spanning && index == len(template)-1 {
			raw = strings.Join(segments[index:], "/")
		}
		value, err := url.PathUnescape(raw)
		if err != nil {
			return 0, nil, false
		}
		values[name] = value
	}
	return score, values, true
}

func lengthMatches(template, segments []string, spanning bool) bool {
	if !spanning {
		return len(template) == len(segments)
	}
	last, isParameter := templateParameter(template[len(template)-1])
	return isParameter && slices.Contains(spanningParameters, last) && len(segments) > len(template)
}

func templateParameter(part string) (string, bool) {
	if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
		return part[1 : len(part)-1], true
	}
	return "", false
}

// servableDescriptor admits only implemented, agent-facing operations that use
// a repository installation credential and neither take sealed input nor return
// a credential.
func servableDescriptor(name string) (opcatalog.Descriptor, error) {
	descriptor, found := opcatalog.ByName(name)
	switch {
	case !found:
		return opcatalog.Descriptor{}, unsupported("operation %s is not cataloged", name)
	case descriptor.Implementation != capability.StatusImplemented || !descriptor.AgentFacing:
		return opcatalog.Descriptor{}, unsupported("operation %s is not available to agents", name)
	case descriptor.CredentialKind != "installation":
		return opcatalog.Descriptor{}, unsupported("operation %s needs a %s credential, which the GitHub-compatible API does not use", name, descriptor.CredentialKind)
	case descriptor.Sealed || descriptor.CredentialOutputKind != nil:
		return opcatalog.Descriptor{}, unsupported("operation %s handles secret material; use the typed Agent API", name)
	}
	return descriptor, nil
}

// Request builds the policy request of the matched call from its path, query,
// and JSON body. The client is added by the caller.
func (m RESTMatch) Request(query url.Values, body []byte) (policy.Request, error) {
	target, err := m.target()
	if err != nil {
		return policy.Request{}, err
	}
	arguments, err := m.arguments(query, body)
	if err != nil {
		return policy.Request{}, err
	}
	attrs, err := singleValues(operations.PolicyAttributes(m.Descriptor.Name, &m.Binding, arguments))
	if err != nil {
		return policy.Request{}, err
	}
	return policy.Request{Operation: policy.Operation(m.Descriptor.Name), Target: target, Attrs: attrs}, nil
}

func (m RESTMatch) target() (policy.Target, error) {
	target := policy.Target{Kind: m.Descriptor.TargetKind}
	for _, parameter := range m.Binding.TargetPathParameters {
		if err := setTargetField(&target, parameter.Field, m.values[parameter.Name]); err != nil {
			return policy.Target{}, err
		}
	}
	if _, _, ok := Repository(target); !ok {
		return policy.Target{}, unsupported("operation %s is not scoped to one repository", m.Descriptor.Name)
	}
	return target, nil
}

func setTargetField(target *policy.Target, field, value string) error {
	switch field {
	case "owner":
		target.Owner = value
	case "repo":
		target.Repo = value
	case "name":
		target.Name = value
	case "number":
		return setPositive(&target.Number, value)
	case "id":
		return setPositive(&target.ID, value)
	default:
		return unsupported("target field %s is not served by the GitHub-compatible API", field)
	}
	return nil
}

func setPositive(field *int64, value string) error {
	number, err := strconv.ParseInt(value, 10, 64)
	if err != nil || number <= 0 {
		return malformed("the request path has an invalid number")
	}
	*field = number
	return nil
}

// Repository returns the repository that a policy target belongs to.
func Repository(target policy.Target) (string, string, bool) {
	repo := target.Repo
	if target.Kind == "repo" {
		repo = target.Name
	}
	return target.Owner, repo, target.Owner != "" && repo != ""
}

func (m RESTMatch) arguments(query url.Values, body []byte) (map[string]any, error) {
	arguments := map[string]any{}
	for name, value := range m.values {
		if !m.targetParameter(name) {
			arguments[name] = value
		}
	}
	for _, parameter := range m.Binding.ArgumentParameters {
		if values, found := query[parameter.Name]; found && parameter.In == "query" {
			arguments[parameter.Name] = queryValue(values)
		}
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return arguments, nil
	}
	var input any
	if err := strictjson.Decode(body, &input, false); err != nil {
		return nil, malformed("the request body is not valid JSON")
	}
	arguments["input"] = input
	return arguments, nil
}

func (m RESTMatch) targetParameter(name string) bool {
	return slices.ContainsFunc(m.Binding.TargetPathParameters, func(parameter opbinding.TargetParameter) bool {
		return parameter.Name == name
	})
}

func queryValue(values []string) any {
	if len(values) == 1 {
		return values[0]
	}
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

// singleValues keeps native requests exact: they carry one value per policy
// attribute, so a call that needs several values is refused, not truncated.
func singleValues(attrs map[string][]string) (map[string]string, error) {
	if len(attrs) == 0 {
		return nil, nil
	}
	result := make(map[string]string, len(attrs))
	for name, values := range attrs {
		if len(values) != 1 {
			return nil, unsupported("policy attribute %s has %d values; send one value per request", name, len(values))
		}
		result[name] = values[0]
	}
	return result, nil
}
