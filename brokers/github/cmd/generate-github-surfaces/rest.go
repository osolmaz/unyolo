package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/capability"
)

type permissionMatch struct {
	Name  string
	Route permissionRoute
}

var supportedMethods = map[string]bool{
	"get": true, "put": true, "post": true, "delete": true, "patch": true, "head": true,
}

var familyByCategory = map[string]string{
	"actions": "workflow", "activity": "notification", "advisories": "advisory", "agent-tasks": "agent_task",
	"apps": "app", "billing": "organization", "campaigns": "campaign", "checks": "check", "classroom": "organization",
	"code-quality": "security", "code-scanning": "code_scanning", "code-security": "security", "codes-of-conduct": "repo",
	"codespaces": "codespace", "copilot": "copilot", "copilot-spaces": "copilot", "credentials": "credential",
	"dependabot": "dependabot", "dependency-graph": "dependabot", "deployments": "deployment", "emojis": "repo",
	"enterprise-team-memberships": "member", "enterprise-team-organizations": "organization", "enterprise-teams": "team",
	"gists": "gist", "git": "git", "gitignore": "repo", "hosted-compute": "runner", "interactions": "organization",
	"issues": "issue", "licenses": "repo", "markdown": "repo", "meta": "app", "migrations": "migration",
	"oidc": "workflow", "orgs": "organization", "packages": "package", "private-registries": "package",
	"projects": "project", "pulls": "pull_request", "rate-limit": "app", "reactions": "reaction", "repos": "repo",
	"search": "repo", "secret-scanning": "secret_scanning", "security-advisories": "advisory", "teams": "team", "users": "member",
}

var targetKinds = []string{
	"advisory", "alert", "app", "artifact", "cache", "check", "codespace", "comment", "commit", "deployment",
	"discussion", "enterprise", "environment", "gist", "installation", "issue", "job", "label", "milestone", "notification",
	"member", "organization", "package", "project", "pull_request", "reaction", "ref", "release", "repo", "ruleset", "run", "security", "team", "user", "webhook", "workflow",
}

//nolint:cyclop // Exhaustive method and source-count checks are kept explicit for review.
func generateREST(state *generatedState, document openAPIDocument, permissions map[string][]permissionMatch) error {
	count := 0
	appEnabled := 0
	paths := make([]string, 0, len(document.Paths))
	for path := range document.Paths {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	for _, path := range paths {
		methods := document.Paths[path]
		methodNames := make([]string, 0, len(methods))
		for method := range methods {
			if supportedMethods[method] {
				methodNames = append(methodNames, method)
			}
		}
		slices.Sort(methodNames)
		for _, method := range methodNames {
			count++
			var operation restOperation
			if err := json.Unmarshal(methods[method], &operation); err != nil {
				return err
			}
			if operation.OperationID == "" {
				return fmt.Errorf("%s %s has no operationId", method, path)
			}
			if enabled, _ := operation.GitHub["enabledForGitHubApps"].(bool); enabled {
				appEnabled++
			}
			generateRESTOperation(state, strings.ToUpper(method), path, operation, permissions, document.Components)
		}
	}
	if count != restExpected {
		return fmt.Errorf("REST operation count = %d, want %d", count, restExpected)
	}
	if appEnabled != 945 {
		return fmt.Errorf("GitHub App-enabled REST operation count = %d, want 945", appEnabled)
	}
	return nil
}

func generateRESTOperation(state *generatedState, method, path string, operation restOperation, permissions map[string][]permissionMatch, components map[string]any) {
	matches := permissions[method+" "+path]
	requiredPermissions := requiredPermissionMap(matches)
	credential := credentialKind(method, path, operation, matches)
	disposition, reason := restDisposition(method, path, operation, credential)
	if disposition == "internal" && credential == "unavailable" {
		credential = "development-token"
	}
	riskClasses := classifyRiskClasses(method, path, operation)
	coverage := restCoverage{UpstreamID: operation.OperationID, Method: method, Path: path, Summary: operation.Summary,
		Disposition: disposition, CredentialKind: credential, RequiredPermissions: requiredPermissions,
		Reason: reason, RiskClasses: riskClasses, Reviewed: true}
	if disposition == "blocked-credential" {
		coverage.RequiredCredential = "classic-pat"
	}
	operations := canonicalRESTOperations(operation.OperationID, path)
	if disposition == "duplicate" || disposition == "blocked-credential" || disposition == "blocked-upstream" || disposition == "local" {
		operations = nil
	}
	for _, name := range operations {
		descriptor := descriptorForREST(name, method, path, operation, disposition, credential, requiredPermissions, riskClasses, components)
		state.descriptors = append(state.descriptors, descriptor)
		coverage.CatalogOperations = append(coverage.CatalogOperations, name)
		state.schemas.Operations[name] = schemasForREST(name, method, path, operation, descriptor.Descriptor, components)
		state.bindings = append(state.bindings, bindingForREST(name, method, path, operation, descriptor.Descriptor, components))
	}
	state.restCoverage = append(state.restCoverage, coverage)
}

func canonicalRESTOperations(operationID, path string) []string {
	if names := reviewedOverrides.RESTOperationNames[operationID]; len(names) > 0 {
		return slices.Clone(names)
	}
	parts := strings.SplitN(operationID, "/", 2)
	category, action := parts[0], parts[0]
	if len(parts) == 2 {
		action = parts[1]
	}
	family := semanticRESTFamily(category, action, path)
	if family == "" {
		family = targetKindForREST(path, "installation")
	}
	if mapped := familyByCategory[category]; mapped != "" && categoryName(family) != category {
		action = category + "-" + action
	}
	action = normalizeIdentifier(action)
	return []string{family + "." + action}
}

func semanticRESTFamily(category, action, path string) string {
	text := strings.ToLower(category + " " + action + " " + path)
	checks := []struct {
		terms  []string
		family string
	}{
		{[]string{"agent-task", "/agents/"}, "agent_task"},
		{[]string{"release", "/releases"}, "release"},
		{[]string{"artifact", "/artifacts"}, "artifact"},
		{[]string{"cache", "/caches", "/actions/cache"}, "cache"},
		{[]string{"runner", "/runners", "hosted-compute"}, "runner"},
		{[]string{"workflow-run", "/actions/runs", "/actions/jobs", "workflow-job"}, "action_run"},
		{[]string{"workflow", "/actions/workflows"}, "workflow"},
		{[]string{"environment", "/environments"}, "environment"},
		{[]string{"deployment", "/deployments"}, "deployment"},
		{[]string{"ruleset", "/rulesets"}, "ruleset"},
		{[]string{"branch-protection", "/protection"}, "branch_protection"},
		{[]string{"code-scanning"}, "code_scanning"},
		{[]string{"secret-scanning"}, "secret_scanning"},
		{[]string{"dependabot", "dependency-graph"}, "dependabot"},
		{[]string{"security-advisory", "/advisories"}, "advisory"},
		{[]string{"discussion", "/discussions"}, "discussion"},
		{[]string{"review-comment", "review-thread", "/reviews"}, "review"},
		{[]string{"pull", "/pulls"}, "pull_request"},
		{[]string{"issue-comment", "/comments"}, "comment"},
		{[]string{"label", "/labels"}, "label"},
		{[]string{"milestone", "/milestones"}, "milestone"},
		{[]string{"reaction", "/reactions"}, "reaction"},
		{[]string{"issue", "/issues"}, "issue"},
		{[]string{"project", "/projects"}, "project"},
		{[]string{"team", "/teams"}, "team"},
		{[]string{"collaborator", "/collaborators"}, "collaborator"},
		{[]string{"member", "/members", "membership"}, "member"},
		{[]string{"organization", "/orgs/"}, "organization"},
		{[]string{"enterprise", "/enterprises/"}, "enterprise"},
		{[]string{"package", "/packages"}, "package"},
		{[]string{"pages", "/pages"}, "pages"},
		{[]string{"codespace", "/codespaces"}, "codespace"},
		{[]string{"gist", "/gists"}, "gist"},
		{[]string{"notification", "/notifications"}, "notification"},
		{[]string{"migration", "/migrations"}, "migration"},
		{[]string{"campaign", "/campaigns"}, "campaign"},
		{[]string{"copilot"}, "copilot"},
		{[]string{"webhook", "/hooks"}, "webhook"},
		{[]string{"installation"}, "installation"},
		{[]string{"commit", "/commits"}, "commit"},
		{[]string{"branch", "/branches"}, "branch"},
		{[]string{"tag", "/tags"}, "tag"},
		{[]string{"/git/refs", "git-ref"}, "git"},
	}
	for _, check := range checks {
		if containsAny(text, check.terms) {
			return check.family
		}
	}
	return familyByCategory[category]
}

func categoryName(family string) string {
	switch family {
	case "repo":
		return "repos"
	case "organization":
		return "orgs"
	case "pull_request":
		return "pulls"
	}
	return family
}

//nolint:cyclop // Security metadata is derived in one auditable classification path.
func descriptorForREST(name, method, path string, operation restOperation, disposition, credential string, permissions map[string]string, classes []string, components map[string]any) opcatalog.Descriptor {
	mutation := method != http.MethodGet && method != http.MethodHead
	credentialOutput := runnerCredentialOutput(operation.OperationID)
	target := targetKindForREST(path, credential)
	sealedInputPaths := sensitiveTopLevelPaths(argumentsSchemaForREST(method, path, operation, target, components))
	if mutation && slices.Contains(classes, "secret") && len(operation.RequestBody) > 0 && !slices.Contains(sealedInputPaths, "input") {
		sealedInputPaths = append(sealedInputPaths, "input")
	}
	slices.Sort(sealedInputPaths)
	mode, dispositionFlags, maxUses := capability.ModeWindow, "W", 100
	if mutation {
		mode, dispositionFlags, maxUses = capability.ModeExecution, "E", 1
	}
	risk := operationRisk(name, classes, method)
	explicit := mutation && (len(classes) > 0 || highOrCriticalRisk(risk)) || credentialOutput != nil
	sealed := len(sealedInputPaths) > 0 || credentialOutput != nil
	if sealed {
		mode, dispositionFlags, maxUses = capability.ModeExecution, "E", 1
	}
	internal := disposition == "internal"
	if explicit {
		dispositionFlags += "/X"
	}
	if sealed {
		dispositionFlags += "/S"
	}
	if internal {
		dispositionFlags += "/I"
	}
	agentFacing := disposition == "implemented" || disposition == "protocol"
	if internal || disposition == "operator-only" {
		agentFacing = false
	}
	var tool, command *string
	if agentFacing {
		toolName := "gh_" + strings.ReplaceAll(name, ".", "_")
		commandName := strings.ReplaceAll(name, ".", " ")
		tool = &toolName
		command = &commandName
	}
	return opcatalog.Descriptor{Descriptor: capability.Descriptor{
		Name: name, OperationRevision: 1, Summary: operation.Summary, Disposition: dispositionFlags,
		AuthorizationMode: mode, ExplicitOnly: explicit, Sealed: sealed, Internal: internal,
		Implementation: implementationStatus(disposition, "rest-binding", agentFacing), Risk: risk, TargetKind: target, MaxUses: maxUses,
		RequestTTLSeconds: 300, ApprovalTTLSeconds: 600, FamilyGlobAllowed: !explicit,
		AgentFacing: agentFacing, MCPTool: tool, CLICommand: command,
		TargetSchema: "target." + target + ".v1", ArgumentSchema: "arguments." + name + ".v1", ResultSchema: "result." + name + ".v1",
		CredentialKind: credential, CredentialOutputKind: credentialOutput,
		SealedInputPaths: sealedInputPaths, UpstreamBindingIDs: []string{"rest:" + operation.OperationID},
		ExecutorKind: executorKind(disposition), ReconcilerKind: reconcilerKind(method, disposition),
	}, RequiredGitHubPermissions: permissions, RequiredRepositorySelection: strings.Contains(path, "/repos/{owner}/{repo}"),
		AllowEmptyInstallationPermissions: slices.Contains(reviewedOverrides.PermissionlessInstallationOperations, operation.OperationID)}
}

func highOrCriticalRisk(risk capability.Risk) bool {
	return risk == capability.RiskHigh || risk == capability.RiskCritical
}

func runnerCredentialOutput(operationID string) *string {
	if !strings.Contains(operationID, "create-registration-token") && !strings.Contains(operationID, "create-remove-token") {
		return nil
	}
	kind := "github-runner-token"
	return &kind
}

//nolint:cyclop // Every coverage disposition maps explicitly to one public implementation status.
func implementationStatus(disposition, executor string, agentFacing bool) capability.ImplementationStatus {
	switch disposition {
	case "internal":
		return capability.StatusInternal
	case "operator-only":
		return capability.StatusOperatorOnly
	case "local":
		return capability.StatusLocal
	case "duplicate":
		return capability.StatusDuplicate
	case "blocked-credential":
		return capability.StatusBlockedCredential
	case "blocked-upstream":
		return capability.StatusBlockedUpstream
	case "protocol":
		return capability.StatusProtocol
	}
	if agentFacing && executor == "persisted-graphql" {
		return capability.StatusGraphQL
	}
	if agentFacing && executor == "rest-binding" {
		return capability.StatusImplemented
	}
	return capability.StatusCataloged
}

func operationRisk(name string, classes []string, method string) capability.Risk {
	if slices.Contains(reviewedOverrides.HighRiskOperations, name) {
		return capability.RiskHigh
	}
	return riskFor(classes, method)
}

func riskFor(classes []string, method string) capability.Risk {
	if slices.Contains(classes, "destructive") || slices.Contains(classes, "secret") || slices.Contains(classes, "billing") || slices.Contains(classes, "enterprise") {
		return capability.RiskCritical
	}
	if len(classes) > 0 {
		return capability.RiskHigh
	}
	if method == http.MethodGet || method == http.MethodHead {
		return capability.RiskLow
	}
	return capability.RiskMedium
}

//nolint:cyclop // Dispositions are an ordered, fail-closed classification table.
func restDisposition(method, path string, operation restOperation, credential string) (string, string) {
	id := operation.OperationID
	text := strings.ToLower(id + " " + path + " " + operation.Summary)
	switch {
	case id == "meta/root" || id == "rate-limit/get" || id == "apps/create-installation-access-token" || id == "credentials/revoke":
		return "internal", "broker credential, health, or control-plane machinery"
	case strings.HasPrefix(path, "/app") || strings.HasPrefix(path, "/applications/") || strings.Contains(text, "oauth"):
		return "operator-only", "GitHub App or OAuth control-plane operation"
	case strings.HasPrefix(id, "markdown/") || strings.HasPrefix(id, "emojis/") || strings.HasPrefix(id, "gitignore/") || strings.HasPrefix(id, "codes-of-conduct/"):
		return "local", "equivalent behavior requires no broker authority"
	case isStreamingOperation(method, path, operation):
		return "protocol", "named bounded binary or redirect-validated stream adapter"
	case credential == "unavailable":
		return "blocked-credential", "official metadata exposes neither installation nor user GitHub App authentication"
	default:
		return "implemented", "typed catalog operation; upstream execution intentionally deferred to later stages"
	}
}

func credentialKind(method, path string, operation restOperation, matches []permissionMatch) string {
	if fixed := fixedCredentialKind(path, operation.OperationID); fixed != "" {
		return fixed
	}
	server, user := false, false
	for _, match := range matches {
		server = server || match.Route.ServerToServer
		user = user || match.Route.UserToServer
	}
	if server {
		return "installation"
	}
	if user {
		return "user"
	}
	if enabled, _ := operation.GitHub["enabledForGitHubApps"].(bool); enabled {
		// Without a reviewed permission route, an installation token cannot be
		// narrowed safely. An enrolled GitHub App user credential remains
		// operation-gated and can serve GitHub-App-compatible endpoints.
		return "user"
	}
	if method == http.MethodGet || method == http.MethodHead {
		return "user"
	}
	return "unavailable"
}

func fixedCredentialKind(path, operationID string) string {
	if strings.HasPrefix(path, "/app") {
		return "app-jwt"
	}
	if slices.Contains(reviewedOverrides.PermissionlessInstallationOperations, operationID) {
		return "installation"
	}
	return ""
}

func requiredPermissionMap(matches []permissionMatch) map[string]string {
	result := map[string]string{}
	for _, match := range matches {
		if !match.Route.ServerToServer && !match.Route.UserToServer {
			continue
		}
		access := match.Route.Access
		if access == "" {
			access = "read"
		}
		if result[match.Name] != "write" || access == "write" {
			result[match.Name] = access
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func classifyRiskClasses(method, path string, operation restOperation) []string {
	if method == http.MethodGet || method == http.MethodHead {
		return nil
	}
	text := strings.ToLower(operation.OperationID + " " + path + " " + operation.Summary)
	secretText := strings.NewReplacer("secret-scanning", "scanning", "secret_scanning", "scanning").Replace(text)
	rules := []struct {
		name  string
		terms []string
	}{
		{"destructive", []string{"delete", "remove", "revoke", "transfer", "archive", "cancel", "terminate"}},
		{"permission", []string{"permission", "role", "member", "collaborator", "access", "suspend", "block", "deploy key"}},
		{"billing", []string{"billing", "spending", "budget", "plan"}},
		{"organization", []string{"/orgs/", "organization"}},
		{"enterprise", []string{"/enterprises/", "enterprise"}},
	}
	var result []string
	for _, rule := range rules {
		if containsAny(text, rule.terms) {
			result = append(result, rule.name)
		}
	}
	if containsAny(secretText, []string{"secret", "private key", "token", "credential"}) {
		result = append(result, "secret")
	}
	slices.Sort(result)
	return result
}

func containsAny(value string, terms []string) bool {
	for _, term := range terms {
		if strings.Contains(value, term) {
			return true
		}
	}
	return false
}

//nolint:cyclop // Resource path precedence and credential-authority fallback are one closed classification table.
func targetKindForREST(path, credential string) string {
	checks := []struct{ token, kind string }{
		{"{enterprise}", "enterprise"}, {"{org}", "organization"}, {"{installation_id}", "installation"},
		{"{team_slug}", "team"}, {"{team_id}", "team"}, {"{pull_number}", "pull_request"}, {"{issue_number}", "issue"},
		{"{discussion_number}", "discussion"}, {"{comment_id}", "comment"}, {"{workflow_id}", "workflow"}, {"{run_id}", "run"},
		{"{job_id}", "job"}, {"{artifact_id}", "artifact"}, {"{cache_id}", "cache"}, {"{deployment_id}", "deployment"},
		{"{environment_name}", "environment"}, {"{release_id}", "release"}, {"{package_name}", "package"},
		{"{codespace_name}", "codespace"}, {"{gist_id}", "gist"}, {"{ruleset_id}", "ruleset"}, {"{alert_number}", "alert"},
		{"{ghsa_id}", "advisory"}, {"{project_id}", "project"}, {"{notification_id}", "notification"},
	}
	for _, check := range checks {
		if strings.Contains(path, check.token) {
			return check.kind
		}
	}
	if strings.Contains(path, "{owner}") && strings.Contains(path, "{repo}") {
		return "repo"
	}
	if strings.HasPrefix(path, "/installation") {
		return "installation"
	}
	if strings.Contains(path, "/orgs/") {
		return "organization"
	}
	if strings.Contains(path, "/users/") || strings.HasPrefix(path, "/user") {
		return "user"
	}
	if strings.HasPrefix(path, "/app") {
		return "app"
	}
	switch credential {
	case "user":
		return "user"
	case "installation":
		return "installation"
	default:
		return "app"
	}
}

func normalizeIdentifier(value string) string {
	value = camelToSnake(value)
	value = strings.NewReplacer("-", "_", "/", "_", ".", "_").Replace(value)
	value = regexp.MustCompile(`_+`).ReplaceAllString(value, "_")
	value = strings.Trim(value, "_")
	if value == "" {
		return "root"
	}
	return value
}

func camelToSnake(value string) string {
	var out strings.Builder
	for index, r := range value {
		if unicode.IsUpper(r) && index > 0 {
			out.WriteByte('_')
		}
		out.WriteRune(unicode.ToLower(r))
	}
	return out.String()
}

func isStreamingOperation(method, path string, operation restOperation) bool {
	return streamDirection(operation.OperationID) != ""
}

func streamDirection(operationID string) string {
	if operationID == "repos/upload-release-asset" {
		return "upload"
	}
	for _, id := range []string{
		"actions/download-artifact",
		"actions/download-job-logs-for-workflow-run",
		"actions/download-workflow-run-attempt-logs",
		"actions/download-workflow-run-logs",
		"migrations/download-archive-for-org",
		"migrations/get-archive-for-authenticated-user",
		"repos/download-tarball-archive",
		"repos/download-zipball-archive",
		"repos/get-release-asset",
	} {
		if operationID == id {
			return "download"
		}
	}
	return ""
}

func executorKind(disposition string) string {
	if disposition == "protocol" {
		return "bounded-stream"
	}
	if disposition == "internal" {
		return "internal"
	}
	if disposition == "operator-only" {
		return "operator"
	}
	return "rest-binding"
}

func reconcilerKind(method, disposition string) string {
	if method == http.MethodGet || method == http.MethodHead || disposition == "internal" {
		return "none"
	}
	if method == http.MethodDelete {
		return "absence-proof"
	}
	return "bounded-readback"
}
