package hubclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
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
	query, err := renderBoundQuery(binding.QueryParameters, target)
	if err != nil {
		return nil, err
	}
	if err := c.call(ctx, callSpec{method: binding.Method, path: path, origin: binding.Origin, query: query, body: body, out: out}); err != nil {
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
	query, err := renderBoundQuery(binding.QueryParameters, target)
	if err != nil {
		return nil, false, err
	}
	err = c.call(ctx, callSpec{method: binding.ObserveMethod, path: path, origin: binding.Origin, query: query, out: &observed})
	if IsNotFound(err) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	return observed, false, nil
}

func renderBoundQuery(names []string, raw json.RawMessage) (url.Values, error) {
	if len(names) == 0 {
		return nil, nil
	}
	var target map[string]any
	if err := strictjson.Decode(raw, &target, true); err != nil {
		return nil, errors.New("hubclient: bound target is invalid")
	}
	query := make(url.Values)
	for _, name := range names {
		value, found := target[name]
		if found && !appendBoundQueryValue(query, name, value) {
			return nil, errors.New("hubclient: bound query fields are invalid")
		}
	}
	return query, nil
}

func appendBoundQueryValue(query url.Values, name string, value any) bool {
	if values, ok := value.([]any); ok {
		for _, item := range values {
			text, valid := scalarQueryValue(item)
			if !valid {
				return false
			}
			query.Add(name, text)
		}
		return true
	}
	text, valid := scalarQueryValue(value)
	if valid {
		query.Add(name, text)
	}
	return valid
}

func scalarQueryValue(value any) (string, bool) {
	switch value := value.(type) {
	case string:
		return value, true
	case bool:
		return strconv.FormatBool(value), true
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64), true
	case json.Number:
		if _, err := strconv.ParseFloat(value.String(), 64); err != nil {
			return "", false
		}
		return value.String(), true
	default:
		return "", false
	}
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
		return value, validScalarPathString(value)
	case float64:
		return scalarPathNumber(value)
	default:
		return "", false
	}
}

func validScalarPathString(value string) bool {
	return value != "" &&
		value != "." &&
		value != ".." &&
		!strings.ContainsAny(value, "/\\\x00")
}

func scalarPathNumber(value float64) (string, bool) {
	if value < 0 || value != float64(int64(value)) {
		return "", false
	}
	return fmt.Sprintf("%d", int64(value)), true
}

func boundBody(binding opbinding.Binding, targetRaw, raw json.RawMessage) (any, error) {
	if binding.Transform != "" {
		return transformBoundBody(binding.Transform, raw)
	}
	arguments, err := decodeBoundArguments(raw)
	if err != nil {
		return nil, err
	}
	if projection := binding.ArgumentProjection; projection != "" {
		return projectedBoundArgument(arguments, projection)
	}
	mergeFixedBody(arguments, binding.FixedBody)
	if err := mergeBodyFromTarget(arguments, binding.BodyFromTarget, targetRaw); err != nil {
		return nil, err
	}
	if len(arguments) == 0 && len(binding.FixedBody) == 0 {
		return nil, nil
	}
	return arguments, nil
}

func decodeBoundArguments(raw json.RawMessage) (map[string]any, error) {
	var arguments map[string]any
	if err := strictjson.Decode(raw, &arguments, true); err != nil {
		return nil, errors.New("hubclient: bound arguments are invalid")
	}
	return arguments, nil
}

func projectedBoundArgument(arguments map[string]any, projection string) (any, error) {
	value, found := arguments[projection]
	if !found {
		return nil, errors.New("hubclient: projected arguments are missing")
	}
	return value, nil
}

func mergeFixedBody(arguments map[string]any, fixed map[string]any) {
	for key, value := range fixed {
		arguments[key] = value
	}
}

func mergeBodyFromTarget(arguments map[string]any, projection map[string]string, targetRaw json.RawMessage) error {
	if len(projection) == 0 {
		return nil
	}
	var target map[string]any
	if err := strictjson.Decode(targetRaw, &target, true); err != nil {
		return errors.New("hubclient: bound target is invalid")
	}
	for bodyKey, targetKey := range projection {
		value, found := target[targetKey]
		if !found {
			return errors.New("hubclient: bound body target field is missing")
		}
		arguments[bodyKey] = value
	}
	return nil
}
