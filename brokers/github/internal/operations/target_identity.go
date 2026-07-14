package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/osolmaz/brokerkit/brokers/github/internal/githubauth"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opbinding"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/schemaregistry"
)

var immutableTargetFields = []string{"id", "node_id"}

func authorizationTargetFields(binding *opbinding.Binding, target map[string]any, credential githubauth.Metadata) map[string][]string {
	trusted := trustedAuthorizationTargetFields(binding, target)
	fields := projectedAuthorizationTargetFields(target, trusted)
	addCredentialTargetFields(fields, binding, target, credential)
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func trustedAuthorizationTargetFields(binding *opbinding.Binding, target map[string]any) map[string]bool {
	trusted := map[string]bool{"id": targetFieldPresent("id", target), "node_id": targetFieldPresent("node_id", target)}
	if binding == nil {
		return trusted
	}
	for _, parameter := range binding.TargetPathParameters {
		trusted[parameter.Field] = true
	}
	trusted["name"] = trusted["name"] || binding.AuthenticatedUserTarget
	return trusted
}

func projectedAuthorizationTargetFields(target map[string]any, trusted map[string]bool) map[string][]string {
	fields := map[string][]string{}
	for _, key := range []string{"owner", "repo", "name", "node_id"} {
		if value := stringValue(target, key); trusted[key] && value != "" {
			fields[key] = []string{value}
		}
	}
	for _, key := range []string{"id", "number"} {
		if value := integerString(target, key); trusted[key] && value != "" {
			fields[key] = []string{value}
		}
	}
	return fields
}

func addCredentialTargetFields(fields map[string][]string, binding *opbinding.Binding, target map[string]any, credential githubauth.Metadata) {
	if credential.InstallationID > 0 {
		fields["installation_id"] = []string{fmt.Sprint(credential.InstallationID)}
	}
	if credential.UserID > 0 && binding != nil && binding.AuthenticatedUserTarget && stringValue(target, "kind") == "user" {
		fields["id"] = []string{fmt.Sprint(credential.UserID)}
	}
}

func (a generatedAdapter) resolveCredential(ctx context.Context, target map[string]any) (githubauth.Metadata, error) {
	credential, err := a.manager.SelectMetadata(ctx, a.descriptor, target, a.options.RequestingUserID)
	if err != nil || a.binding == nil || !a.binding.AuthenticatedUserTarget {
		return credential, err
	}
	return credential, a.manager.ValidateAuthenticatedUserTarget(ctx, credential, target)
}

func (a generatedAdapter) resolveTarget(ctx context.Context, target, arguments map[string]any) (map[string]any, githubauth.Metadata, json.RawMessage, error) {
	credential, err := a.resolveCredential(ctx, target)
	if err != nil {
		return nil, githubauth.Metadata{}, nil, err
	}
	target, err = a.verifyTargetIdentity(ctx, credential, target, arguments)
	if err != nil {
		return nil, githubauth.Metadata{}, nil, err
	}
	encoded, err := json.Marshal(target)
	if err != nil {
		return nil, githubauth.Metadata{}, nil, errors.New("GitHub operation target is invalid")
	}
	return target, credential, encoded, nil
}

func (a generatedAdapter) verifyTargetIdentity(ctx context.Context, credential githubauth.Metadata, target, arguments map[string]any) (map[string]any, error) {
	fields := unboundImmutableFields(a.binding, target)
	if len(fields) == 0 {
		return target, nil
	}
	resolver, found := targetIdentityResolver(a.descriptor.TargetKind, a.binding, fields)
	if !found {
		return nil, errors.New("GitHub target contains an unverified immutable identifier")
	}
	resolved, err := a.resolveTargetIdentity(ctx, credential, resolver, target, arguments)
	if err != nil || !matchingTargetIdentity(target, resolved, fields) {
		return nil, errors.New("GitHub target immutable identifier does not match its resource path")
	}
	for _, field := range fields {
		target[field] = resolved[field]
	}
	return target, nil
}

func (a generatedAdapter) resolveTargetIdentity(ctx context.Context, credential githubauth.Metadata, resolver opbinding.Binding,
	target, arguments map[string]any) (map[string]any, error) {
	result, err := a.manager.ExecuteREST(ctx, credential, resolver, target, arguments)
	if err != nil || executionStatusError(resolver, result.StatusCode) != nil || schemaregistry.ValidateResult(resolver.Operation, result.Body) != nil {
		return nil, errors.New("GitHub target identity could not be verified")
	}
	resolved, err := decodeObject(result.Body)
	if err != nil {
		return nil, errors.New("GitHub target identity could not be verified")
	}
	return resolved, nil
}

func unboundImmutableFields(binding *opbinding.Binding, target map[string]any) []string {
	result := []string{}
	for _, field := range immutableTargetFields {
		if !targetFieldPresent(field, target) || bindingUsesTargetField(binding, field) {
			continue
		}
		result = append(result, field)
	}
	return result
}

func bindingUsesTargetField(binding *opbinding.Binding, field string) bool {
	return binding != nil && slices.ContainsFunc(binding.TargetPathParameters, func(parameter opbinding.TargetParameter) bool {
		return parameter.Field == field
	})
}

func targetIdentityResolver(kind string, binding *opbinding.Binding, fields []string) (opbinding.Binding, bool) {
	if binding == nil {
		return opbinding.Binding{}, false
	}
	bindings, err := opbinding.All()
	if err != nil {
		return opbinding.Binding{}, false
	}
	index := slices.IndexFunc(bindings, func(candidate opbinding.Binding) bool {
		return isTargetIdentityResolver(candidate, kind, binding.PathTemplate, fields)
	})
	if index < 0 {
		return opbinding.Binding{}, false
	}
	return bindings[index], true
}

func isTargetIdentityResolver(candidate opbinding.Binding, kind, path string, fields []string) bool {
	descriptor, found := opcatalog.ByName(candidate.Operation)
	return found && descriptor.TargetKind == kind && candidate.Method == http.MethodGet && candidate.PathTemplate == path &&
		containsProjectionFields(candidate.ResponseProjection, fields)
}

func containsProjectionFields(projection, fields []string) bool {
	for _, field := range fields {
		if !slices.Contains(projection, field) {
			return false
		}
	}
	return true
}

func matchingTargetIdentity(target, resolved map[string]any, fields []string) bool {
	for _, field := range fields {
		if field == "id" {
			if integerString(target, field) == "" || integerString(target, field) != integerString(resolved, field) {
				return false
			}
			continue
		}
		if stringValue(target, field) == "" || stringValue(target, field) != stringValue(resolved, field) {
			return false
		}
	}
	return true
}
