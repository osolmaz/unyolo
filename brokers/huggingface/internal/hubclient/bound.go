package hubclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opbinding"
	"github.com/osolmaz/brokerkit/internal/strictjson"
)

var pathFieldPattern = regexp.MustCompile(`\{([A-Za-z][A-Za-z0-9]*)\}`)

// ExecuteBound executes one operation whose method and path are fixed in the
// embedded provider registry. Requesters cannot supply transport metadata.
func (c *Client) ExecuteBound(ctx context.Context, operation string, target, arguments json.RawMessage) error {
	_, err := c.executeBound(ctx, operation, target, arguments, false)
	return err
}

// ExecuteBoundResult executes a fixed operation and returns its bounded JSON
// result for an adapter that must consume generated provider material.
func (c *Client) ExecuteBoundResult(ctx context.Context, operation string, target, arguments json.RawMessage) (json.RawMessage, error) {
	return c.executeBound(ctx, operation, target, arguments, true)
}

func (c *Client) executeBound(ctx context.Context, operation string, target, arguments json.RawMessage, capture bool) (json.RawMessage, error) {
	binding, found := opbinding.ByName(operation)
	if !found {
		return nil, errors.New("hubclient: fixed operation is not registered")
	}
	path, err := renderBoundPath(binding.Path, binding.FixedPath, target)
	if err != nil {
		return nil, err
	}
	body, err := boundBody(binding, target, arguments)
	if err != nil {
		return nil, err
	}
	var result json.RawMessage
	var out any
	if capture {
		out = &result
	}
	if err := c.call(ctx, callSpec{method: binding.Method, path: path, origin: binding.Origin, body: body, out: out}); err != nil {
		return nil, err
	}
	return result, nil
}

// ObserveBound returns a canonical bounded observation for a registered
// operation. A not-found response is returned as absent without exposing an
// upstream response body.
func (c *Client) ObserveBound(ctx context.Context, operation string, target json.RawMessage) (json.RawMessage, bool, error) {
	binding, found := opbinding.ByName(operation)
	if !found || binding.ObserveMethod == "" {
		return nil, false, errors.New("hubclient: fixed operation has no observation")
	}
	path, err := renderBoundPath(binding.ObservePath, binding.FixedPath, target)
	if err != nil {
		return nil, false, err
	}
	var observed json.RawMessage
	err = c.call(ctx, callSpec{method: binding.ObserveMethod, path: path, origin: binding.Origin, out: &observed})
	if IsNotFound(err) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	return observed, false, nil
}

func renderBoundPath(template string, fixed map[string]any, raw json.RawMessage) (string, error) {
	var target map[string]any
	if err := strictjson.Decode(raw, &target, true); err != nil {
		return "", errors.New("hubclient: bound target is invalid")
	}
	failed := false
	path := pathFieldPattern.ReplaceAllStringFunc(template, func(match string) string {
		name := pathFieldPattern.FindStringSubmatch(match)[1]
		value, found := fixed[name]
		if !found {
			value, found = target[name]
		}
		text, valid := scalarPathValue(value)
		if !found || !valid {
			failed = true
			return ""
		}
		return url.PathEscape(text)
	})
	if failed || strings.ContainsAny(path, "?#") || !strings.HasPrefix(path, "/") {
		return "", errors.New("hubclient: bound path fields are invalid")
	}
	return path, nil
}

func scalarPathValue(value any) (string, bool) {
	switch value := value.(type) {
	case string:
		valid := value != "" && value != "." && value != ".." &&
			!strings.ContainsAny(value, "/\\\x00")
		return value, valid
	case float64:
		if value < 0 || value != float64(int64(value)) {
			return "", false
		}
		return fmt.Sprintf("%d", int64(value)), true
	default:
		return "", false
	}
}

//nolint:cyclop // Binding projections are explicit and tracked by the exact HF CRAP baseline.
func boundBody(binding opbinding.Binding, targetRaw, raw json.RawMessage) (any, error) {
	if binding.Transform != "" {
		return transformBoundBody(binding.Transform, raw)
	}
	var arguments map[string]any
	if err := strictjson.Decode(raw, &arguments, true); err != nil {
		return nil, errors.New("hubclient: bound arguments are invalid")
	}
	if binding.ArgumentProjection != "" {
		value, found := arguments[binding.ArgumentProjection]
		if !found {
			return nil, errors.New("hubclient: projected arguments are missing")
		}
		return value, nil
	}
	for key, value := range binding.FixedBody {
		arguments[key] = value
	}
	if len(binding.BodyFromTarget) > 0 {
		var target map[string]any
		if err := strictjson.Decode(targetRaw, &target, true); err != nil {
			return nil, errors.New("hubclient: bound target is invalid")
		}
		for bodyKey, targetKey := range binding.BodyFromTarget {
			value, found := target[targetKey]
			if !found {
				return nil, errors.New("hubclient: bound body target field is missing")
			}
			arguments[bodyKey] = value
		}
	}
	if len(arguments) == 0 && len(binding.FixedBody) == 0 {
		return nil, nil
	}
	return arguments, nil
}
