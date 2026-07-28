package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/osolmaz/unyolo/brokers/github/internal/opcatalog"
	"github.com/osolmaz/unyolo/operation/capability"
)

func generateGraphQL(state *generatedState, response graphqlResponse, fingerprint string) error {
	types := make(map[string]introspectionType, len(response.Data.Schema.Types))
	for _, value := range response.Data.Schema.Types {
		types[value.Name] = value
	}
	query := types[response.Data.Schema.QueryType.Name]
	mutation := types[response.Data.Schema.MutationType.Name]
	activeQueries, activeMutations := 0, 0
	state.manifest = graphqlManifest{Version: 1, SchemaFingerprint: fingerprint}
	for _, root := range []struct {
		name   string
		fields []introspectionField
	}{{"query", query.Fields}, {"mutation", mutation.Fields}} {
		for _, field := range root.fields {
			if field.IsDeprecated {
				state.graphqlCoverage = append(state.graphqlCoverage, graphqlCoverage{RootType: root.name, Field: field.Name, Deprecated: true,
					Disposition: "blocked-upstream", Reason: nonEmpty(field.DeprecationReason, "deprecated by the pinned GitHub schema"), Reviewed: true})
				continue
			}
			if root.name == "query" {
				activeQueries++
			} else {
				activeMutations++
			}
			operation := canonicalGraphQLOperation(root.name, field.Name)
			document, variables, projection, resultSchema := persistedGraphQLDocument(root.name, field, types)
			digest := sha256.Sum256([]byte(document))
			digestString := hex.EncodeToString(digest[:])
			credential := "user"
			persisted := persistedDocument{CatalogOperation: operation, RootType: root.name, RootField: field.Name,
				OperationName: graphqlOperationName(root.name, field.Name), Document: document, SHA256: digestString,
				VariableSchema: variables, ResponseProjection: projection, ExpectedCost: 1, CredentialKind: credential}
			state.manifest.Documents = append(state.manifest.Documents, persisted)
			disposition := graphqlRootDisposition(field.Name)
			state.graphqlCoverage = append(state.graphqlCoverage, graphqlCoverage{RootType: root.name, Field: field.Name,
				Disposition: disposition, CatalogOperation: operation, RequiredCredential: credential, PersistedDigest: digestString, Reviewed: true})
			descriptor := descriptorForGraphQL(operation, root.name, field, digestString, disposition, variables)
			state.descriptors = append(state.descriptors, descriptor)
			if operation == "pull_request.merge_admin" {
				state.schemas.Operations[operation] = operationSchemas{Target: descriptor.TargetSchema, Arguments: adminMergeArgumentSchema(), Result: adminMergeResultSchema()}
			} else {
				state.schemas.Operations[operation] = operationSchemas{Target: descriptor.TargetSchema, Arguments: variables, Result: resultSchema}
			}
		}
	}
	if activeQueries != activeQueryRoots || activeMutations != activeMutationRoots {
		return fmt.Errorf("active GraphQL roots = %d query/%d mutation, want %d/%d", activeQueries, activeMutations, activeQueryRoots, activeMutationRoots)
	}
	slices.SortFunc(state.manifest.Documents, func(a, b persistedDocument) int { return strings.Compare(a.CatalogOperation, b.CatalogOperation) })
	return nil
}

func descriptorForGraphQL(name, root string, field introspectionField, digest, disposition string, variables map[string]any) opcatalog.Descriptor {
	if name == "pull_request.merge_admin" {
		tool, command := "gh_pull_request_merge_admin", "pull_request merge_admin"
		return opcatalog.Descriptor{Descriptor: capability.Descriptor{Name: name, OperationRevision: 1, Summary: "Admin merge a pull request",
			Disposition: "E/X/O", AuthorizationMode: capability.ModeExecution, ExplicitOnly: true,
			Implementation: capability.StatusImplemented, Risk: capability.RiskHigh,
			TargetKind: "pull_request", MaxUses: 1, RequestTTLSeconds: 300, ApprovalTTLSeconds: 600,
			FamilyGlobAllowed: false, AgentFacing: true, MCPTool: &tool, CLICommand: &command,
			TargetSchema: "target.pull_request.v1", ArgumentSchema: "arguments." + name + ".v1", ResultSchema: "result." + name + ".v1",
			CredentialKind: "user", UpstreamBindingIDs: []string{"graphql:" + digest},
			ExecutorKind: "admin-merge", ReconcilerKind: "pull-request-state"}, DelegatedUserCredential: true}
	}
	mutation := root == "mutation"
	sealedInputPaths := sensitiveTopLevelPaths(variables)
	mode, flags, maxUses := capability.ModeWindow, "W", 100
	if mutation {
		mode, flags, maxUses = capability.ModeExecution, "E", 1
	}
	classes := classifyGraphQLRiskClasses(root, field.Name)
	explicit := mutation && len(classes) > 0
	sealed := len(sealedInputPaths) > 0
	if sealed {
		mode, flags, maxUses = capability.ModeExecution, "E", 1
	}
	if explicit {
		flags += "/X"
	}
	if sealed {
		flags += "/S"
	}
	internal := disposition == "internal"
	agentFacing := false // GraphQL roots require reviewed target-variable bindings before agent exposure.
	if internal {
		flags += "/I"
	} else {
		flags += "/O"
	}
	var tool, command *string
	if agentFacing {
		toolName := "gh_" + strings.ReplaceAll(name, ".", "_")
		commandName := strings.ReplaceAll(name, ".", " ")
		tool, command = &toolName, &commandName
	}
	target := graphqlTargetKind(field.Name)
	return opcatalog.Descriptor{Descriptor: capability.Descriptor{Name: name, OperationRevision: 1, Summary: nonEmpty(field.Description, "GitHub GraphQL "+field.Name),
		Disposition: flags, AuthorizationMode: mode, ExplicitOnly: explicit, Sealed: sealed,
		Implementation: map[bool]capability.ImplementationStatus{true: capability.StatusInternal, false: capability.StatusOperatorOnly}[internal], Risk: riskFor(classes, map[bool]string{true: "POST", false: "GET"}[mutation]),
		TargetKind: target, MaxUses: maxUses, RequestTTLSeconds: 300, ApprovalTTLSeconds: 600,
		Internal: internal, FamilyGlobAllowed: !explicit, AgentFacing: agentFacing, MCPTool: tool, CLICommand: command,
		TargetSchema: "target." + target + ".v1", ArgumentSchema: "arguments." + name + ".v1", ResultSchema: "result." + name + ".v1",
		CredentialKind: "user", SealedInputPaths: sealedInputPaths, UpstreamBindingIDs: []string{"graphql:" + digest},
		ExecutorKind: "persisted-graphql", ReconcilerKind: "none"}}
}

func graphqlRootDisposition(field string) string {
	if slices.Contains(reviewedOverrides.InternalGraphQLRoots, field) {
		return "internal"
	}
	return "graphql"
}

func canonicalGraphQLOperation(root, field string) string {
	if root == "mutation" && field == "mergePullRequest" {
		return "pull_request.merge_admin"
	}
	family := graphqlTargetKind(field)
	action := normalizeIdentifier(field)
	if root == "query" && !strings.Contains(action, "read") && !strings.Contains(action, "list") && !strings.Contains(action, "search") {
		action = "read_" + action
	}
	return family + "." + action
}

func graphqlTargetKind(field string) string {
	value := strings.ToLower(field)
	checks := []struct{ token, family string }{
		{"enterprise", "enterprise"}, {"organization", "organization"}, {"repository", "repo"}, {"pullrequest", "pull_request"},
		{"discussion", "discussion"}, {"issue", "issue"}, {"comment", "comment"}, {"project", "project"}, {"team", "team"},
		{"member", "member"}, {"user", "user"}, {"label", "label"}, {"milestone", "milestone"}, {"reaction", "reaction"},
		{"sponsor", "member"}, {"advisory", "advisory"}, {"security", "security"}, {"workflow", "workflow"}, {"deployment", "deployment"},
	}
	for _, check := range checks {
		if strings.Contains(value, check.token) {
			return check.family
		}
	}
	if strings.Contains(value, "node") || strings.Contains(value, "relay") || strings.Contains(value, "search") {
		return "repo"
	}
	return "repo"
}

func persistedGraphQLDocument(root string, field introspectionField, types map[string]introspectionType) (string, map[string]any, []string, map[string]any) {
	definitions := []string{}
	arguments := []string{}
	properties := map[string]any{}
	required := []string{}
	for _, argument := range field.Args {
		if argument.Name == "first" {
			arguments = append(arguments, "first: 25")
			continue
		}
		if argument.Name == "last" {
			continue
		}
		variable := safeGraphQLName(argument.Name)
		definitions = append(definitions, "$"+variable+": "+graphqlType(argument.Type))
		arguments = append(arguments, argument.Name+": $"+variable)
		properties[variable] = schemaForGraphQLInput(argument.Type, types, map[string]bool{})
		if argument.Type.Kind == "NON_NULL" && argument.DefaultValue == nil {
			required = append(required, variable)
		}
	}
	selection := graphqlSelection(field.Type, types)
	operationName := graphqlOperationName(root, field.Name)
	definitionText := ""
	if len(definitions) > 0 {
		definitionText = "(" + strings.Join(definitions, ", ") + ")"
	}
	argumentText := ""
	if len(arguments) > 0 {
		argumentText = "(" + strings.Join(arguments, ", ") + ")"
	}
	document := fmt.Sprintf("%s %s%s { %s%s%s }", root, operationName, definitionText, field.Name, argumentText, selection)
	variableSchema := map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		variableSchema["required"] = required
	}
	projection := []string{field.Name}
	resultSchema := map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type":    "object",
		"properties": map[string]any{
			field.Name: graphqlResultSchema(field.Type, types),
		},
		"required":             []string{field.Name},
		"additionalProperties": false,
	}
	return document, variableSchema, projection, resultSchema
}

func graphqlSelection(ref typeRef, types map[string]introspectionType) string {
	base := ref
	for base.OfType != nil {
		base = *base.OfType
	}
	if base.Kind == "SCALAR" || base.Kind == "ENUM" {
		return ""
	}
	for _, field := range types[base.Name].Fields {
		if field.Name == "clientMutationId" {
			return " { __typename clientMutationId }"
		}
	}
	return " { __typename }"
}

//nolint:cyclop // GraphQL result kinds and nullability are converted through one exhaustive schema path.
func graphqlResultSchema(ref typeRef, types map[string]introspectionType) map[string]any {
	base := ref
	nullable := true
	if base.Kind == "NON_NULL" && base.OfType != nil {
		base = *base.OfType
		nullable = false
	}
	var result map[string]any
	switch base.Kind {
	case "LIST":
		result = map[string]any{"type": "array", "items": graphqlResultSchema(*base.OfType, types), "maxItems": 100}
	case "SCALAR":
		result = map[string]any{"type": "string", "maxLength": 1 << 20}
		switch base.Name {
		case "Boolean":
			result = map[string]any{"type": "boolean"}
		case "Float":
			result = map[string]any{"type": "number"}
		case "Int":
			result = map[string]any{"type": "integer"}
		}
	case "ENUM":
		result = schemaForGraphQLInput(base, types, map[string]bool{})
	default:
		properties := map[string]any{}
		required := []string{}
		for _, field := range types[base.Name].Fields {
			switch field.Name {
			case "clientMutationId":
				properties["clientMutationId"] = map[string]any{"type": "string", "maxLength": 1 << 20}
			}
		}
		properties["__typename"] = map[string]any{"type": "string", "maxLength": 255}
		required = append(required, "__typename")
		result = map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
		if len(required) > 0 {
			result["required"] = required
		}
	}
	if nullable {
		result["type"] = []any{result["type"], "null"}
	}
	return result
}

func graphqlType(ref typeRef) string {
	switch ref.Kind {
	case "NON_NULL":
		return graphqlType(*ref.OfType) + "!"
	case "LIST":
		return "[" + graphqlType(*ref.OfType) + "]"
	default:
		return ref.Name
	}
}

func graphqlOperationName(root, field string) string {
	value := root + "_" + field
	var out strings.Builder
	upper := true
	for _, r := range value {
		if r == '_' || r == '-' {
			upper = true
			continue
		}
		if upper {
			r = unicode.ToUpper(r)
			upper = false
		}
		out.WriteRune(r)
	}
	return out.String()
}

func safeGraphQLName(value string) string {
	value = normalizeIdentifier(value)
	if value == "type" {
		return "resource_type"
	}
	return value
}

func adminMergeArgumentSchema() map[string]any {
	return map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "additionalProperties": false,
		"properties": map[string]any{
			"merge_method":   map[string]any{"type": "string", "enum": []string{"merge", "squash", "rebase"}},
			"commit_title":   map[string]any{"type": "string", "maxLength": 1024},
			"commit_message": map[string]any{"type": "string", "maxLength": 1 << 20},
		},
		"required": []string{"merge_method"},
	}
}

func adminMergeResultSchema() map[string]any {
	return map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "additionalProperties": false,
		"properties": map[string]any{
			"merged":       map[string]any{"type": "boolean", "const": true},
			"head_sha":     map[string]any{"type": "string", "pattern": "^[0-9a-fA-F]{40,64}$"},
			"merge_method": map[string]any{"type": "string", "enum": []string{"merge", "squash", "rebase"}},
		},
		"required": []string{"merged", "head_sha", "merge_method"},
	}
}

func classifyGraphQLRiskClasses(root, field string) []string {
	if root != "mutation" {
		return nil
	}
	text := strings.ToLower(field)
	rules := []struct {
		name  string
		terms []string
	}{
		{"destructive", []string{"delete", "remove", "revoke", "abort", "cancel", "terminate", "transfer", "archive"}},
		{"permission", []string{"permission", "role", "member", "admin", "access", "block", "bypass"}},
		{"billing", []string{"billing", "sponsor", "invoice", "budget", "plan"}},
		{"organization", []string{"organization"}}, {"enterprise", []string{"enterprise"}},
	}
	var result []string
	for _, rule := range rules {
		if containsAny(text, rule.terms) {
			result = append(result, rule.name)
		}
	}
	if !strings.Contains(text, "secretscanning") && containsAny(text, []string{"secret", "key", "token", "credential"}) {
		result = append(result, "secret")
	}
	if field == "mergePullRequest" {
		result = append(result, "destructive")
	}
	slices.Sort(result)
	return result
}

func nonEmpty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}
