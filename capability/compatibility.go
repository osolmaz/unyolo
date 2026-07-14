package capability

import (
	"fmt"
	"sort"
	"strings"
)

type MCPFieldClass string

const (
	MCPFieldSafe      MCPFieldClass = "safe"
	MCPFieldSensitive MCPFieldClass = "sensitive"
	MCPFieldCollision MCPFieldClass = "collision"
)

// MCPCompatibilityProfile is a provider-neutral approximation of supported
// host structured-field redaction. Providers must project public collisions;
// genuine secrets remain protected rather than renamed around the profile.
type MCPCompatibilityProfile struct{}

var sensitiveExactNames = map[string]bool{
	"apikey": true, "api_key": true, "api-key": true, "apitoken": true, "api_token": true, "api-token": true,
	"bearertoken": true, "bearer_token": true, "bearer-token": true, "token": true, "secret": true,
	"password": true, "passwd": true, "credential": true, "credentials": true, "authorization": true,
	"privatekey": true, "private_key": true, "private-key": true, "access_token": true, "refresh_token": true,
	"accesstoken": true, "refreshtoken": true, "id_token": true, "idtoken": true, "auth_token": true, "authtoken": true,
	"client_secret": true, "clientsecret": true, "app_secret": true, "appsecret": true, "secret_value": true,
	"raw_secret": true, "secret_input": true, "key": true, "key_material": true, "jwt": true, "session": true,
	"signature": true, "cookie": true, "set_cookie": true, "card_number": true, "card_cvc": true,
	"card_cvv": true, "cvc": true, "cvv": true, "security_code": true, "payment_credential": true,
	"shared_payment_token": true,
}

var transcriptSafeExactNames = map[string]bool{
	"request_id": true, "operation_id": true, "transfer_id": true, "commit_signature": true,
	"public_material": true, "armored_public_material": true, "cache_identifier": true,
	"document_name": true, "variable_name": true, "secret_name": true, "hide_sensitive_value": true,
	"object_path": true,
}

var sensitiveSuffixes = []string{
	"_api_key", "-api-key", "_api_token", "-api-token", "_bearer_token", "-bearer-token",
	"_access_token", "-access-token", "_refresh_token", "-refresh-token", "_auth_token", "-auth-token",
	"_private_key", "-private-key", "_key", "-key", "_token", "-token", "_secret", "-secret",
	"_password", "-password", "_passwd", "-passwd", "_credential", "-credential", "_credentials", "-credentials",
	"_authorization", "-authorization", "_signature", "-signature", "_session", "-session", "_cookie", "-cookie",
}

func (MCPCompatibilityProfile) Classify(name string, protected bool) MCPFieldClass {
	if !sensitiveFieldName(name) {
		return MCPFieldSafe
	}
	if protected {
		return MCPFieldSensitive
	}
	return MCPFieldCollision
}

func sensitiveFieldName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if transcriptSafeExactNames[name] {
		return false
	}
	if sensitiveExactNames[name] {
		return true
	}
	for _, suffix := range sensitiveSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

type MCPCompatibilityIssue struct {
	Path string
	Name string
}

func (i MCPCompatibilityIssue) Error() string {
	return fmt.Sprintf("public MCP schema property %s collides with host redaction", i.Path)
}

// AuditMCPPublicSchema returns deterministic unresolved public collisions.
func AuditMCPPublicSchema(schema map[string]any) []MCPCompatibilityIssue {
	issues := []MCPCompatibilityIssue{}
	auditSchemaProperties(schema, "", &issues)
	sort.Slice(issues, func(i, j int) bool { return issues[i].Path < issues[j].Path })
	return issues
}

// AuditMCPToolSchema excludes the explicitly write-only sealed_arguments
// subtree and audits every model-visible tool property.
func AuditMCPToolSchema(schema map[string]any) []MCPCompatibilityIssue {
	public := cloneSchema(schema)
	if properties, ok := public["properties"].(map[string]any); ok {
		delete(properties, "sealed_arguments")
	}
	return AuditMCPPublicSchema(public)
}

func auditSchemaProperties(schema map[string]any, path string, issues *[]MCPCompatibilityIssue) {
	properties, _ := schema["properties"].(map[string]any)
	for name, raw := range properties {
		childPath := path + "/" + escapeJSONPointerToken(name)
		if (MCPCompatibilityProfile{}).Classify(name, false) == MCPFieldCollision {
			*issues = append(*issues, MCPCompatibilityIssue{Path: childPath, Name: name})
		}
		if child, ok := raw.(map[string]any); ok {
			auditSchemaProperties(child, childPath, issues)
		}
	}
	if items, ok := schema["items"].(map[string]any); ok {
		auditSchemaProperties(items, path+"/*", issues)
	}
	for _, item := range schemaBranches(schema["prefixItems"]) {
		auditSchemaProperties(item, path+"/*", issues)
	}
	if additional, ok := schema["additionalProperties"].(map[string]any); ok {
		auditSchemaProperties(additional, path+"/*", issues)
	}
	for _, keyword := range []string{"allOf", "anyOf", "oneOf"} {
		for _, branch := range schemaBranches(schema[keyword]) {
			auditSchemaProperties(branch, path, issues)
		}
	}
}
