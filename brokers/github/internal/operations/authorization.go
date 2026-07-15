package operations

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/osolmaz/brokerkit/brokers/github/internal/githubauth"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opbinding"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/targetregistry"
)

func targetSummary(kind string, target map[string]any) string {
	if owner, repo, ok := targetregistry.RepositoryIdentity(target); ok {
		return owner + "/" + repo
	}
	if name := stringValue(target, "name"); name != "" {
		return kind + " " + name
	}
	if number := integerString(target, "number"); number != "" {
		return kind + " #" + number
	}
	if id := integerString(target, "id"); id != "" {
		return kind + " " + id
	}
	return kind
}

func authorizeDescriptor(descriptor opcatalog.Descriptor, binding *opbinding.Binding, target, arguments map[string]any,
	credential githubauth.Metadata) Authorization {
	attrs := authorizationAttrs(arguments)
	attrs = normalizeOperationAuthorizationAttrs(descriptor.Name, attrs)
	selectors := authorizationSelectorAttrs(binding, arguments)
	if attrs == nil && (len(selectors) > 0 || credential.UserID > 0) {
		attrs = map[string][]string{}
	}
	for key, values := range selectors {
		attrs[key] = values
	}
	if credential.UserID > 0 {
		attrs["actor_id"] = []string{fmt.Sprint(credential.UserID)}
	}
	return Authorization{
		Operation:      descriptor.Name,
		TargetKind:     descriptor.TargetKind,
		TargetFields:   authorizationTargetFields(binding, target, credential),
		Attrs:          attrs,
		CredentialKind: descriptor.CredentialKind,
	}
}

func authorizationSelectorAttrs(binding *opbinding.Binding, arguments map[string]any) map[string][]string {
	if binding == nil || len(binding.AuthorizationParameters) == 0 {
		return nil
	}
	result := make(map[string][]string, len(binding.AuthorizationParameters))
	for _, parameter := range binding.AuthorizationParameters {
		if values := scalarStrings(arguments[parameter.Name]); len(values) > 0 {
			result[parameter.Attribute] = values
		}
	}
	return result
}

func authorizationAttrs(arguments map[string]any) map[string][]string {
	fields := map[string][]string{}
	collectAuthorizationAttrs(arguments, fields)
	for key, values := range fields {
		slices.Sort(values)
		fields[key] = slices.Compact(values)
	}
	if len(fields) == 0 {
		return nil
	}
	return fields
}

// collectAuthorizationAttrs walks only decoded, schema-validated input and
// maps reviewed GitHub field names into the closed policy vocabulary.
func collectAuthorizationAttrs(value any, fields map[string][]string) {
	switch typed := value.(type) {
	case map[string]any:
		for name, child := range typed {
			if attribute, found := authorizationAttributeName(name); found {
				values := scalarStrings(child)
				if name == "branch" {
					for index, value := range values {
						values[index] = canonicalBranchRef(value)
					}
				}
				fields[attribute] = append(fields[attribute], values...)
			}
			collectAuthorizationAttrs(child, fields)
		}
	case []any:
		for _, child := range typed {
			collectAuthorizationAttrs(child, fields)
		}
	}
}

func authorizationAttributeName(name string) (string, bool) {
	aliases := map[string]string{
		"actor_id": "actor_id", "actorId": "actor_id", "actor_login": "actor_login", "actorLogin": "actor_login",
		"base": "base_ref", "base_ref": "base_ref", "baseRef": "base_ref", "environment": "environment",
		"environment_name": "environment", "environmentName": "environment", "head": "head_ref", "head_ref": "head_ref",
		"headRef": "head_ref", "label": "label", "labels": "label", "merge_method": "merge_method", "mergeMethod": "merge_method",
		"branch": "ref", "path": "path", "paths": "path", "permission": "permission", "ref": "ref", "release_state": "release_state",
		"releaseState": "release_state", "resource_id": "resource_id", "resourceId": "resource_id", "role": "role",
		"visibility": "visibility", "workflow": "workflow", "workflow_ref": "workflow_ref", "workflowRef": "workflow_ref",
		"name": "resource_name", "owner": "resource_owner",
	}
	attribute, found := aliases[name]
	return attribute, found
}

func scalarStrings(value any) []string {
	switch typed := value.(type) {
	case string:
		if value := strings.TrimSpace(typed); value != "" {
			return []string{value}
		}
	case json.Number:
		return []string{typed.String()}
	case []any:
		values := []string{}
		for _, child := range typed {
			values = append(values, scalarStrings(child)...)
		}
		return values
	}
	return nil
}
