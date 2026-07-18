package credentialauth

import (
	"strings"

	"github.com/osolmaz/brokerkit/providercredential"
)

func operationRequirement(operation string) (providercredential.Requirement, bool) {
	permission, binding, known := hfPermission(operation)
	if !known {
		return providercredential.Requirement{}, false
	}
	if permission == "" {
		return providercredential.Requirement{}, true
	}
	alternatives := []providercredential.Need{{Permission: permission, MinimumAccessLevel: permissionAccess(permission), TargetBinding: binding}}
	for _, fallback := range []string{"resource", "owner", "namespace"} {
		if fallback != binding {
			alternatives = append(alternatives, providercredential.Need{Permission: permission, MinimumAccessLevel: permissionAccess(permission), TargetBinding: fallback})
		}
	}
	return providercredential.Requirement{AllOf: []providercredential.AnyOf{{Alternatives: alternatives}}}, true
}

func hfPermission(operation string) (permission, binding string, known bool) {
	family, action, found := strings.Cut(operation, ".")
	if !found {
		return "", "", false
	}
	switch family {
	case "auth", "identity", "catalog":
		return "", "", true
	case "bucket":
		return readWritePermission(action, "repo.content.read", "repo.write", "namespace")
	case "collection":
		return readWritePermission(action, "collection.read", "collection.write", "owner")
	case "dataset":
		return "repo.content.read", "owner", true
	case "discussion":
		if readAction(action) {
			return "repo.content.read", "owner", true
		}
		return "discussion.write", "owner", true
	case "endpoint":
		if action == "catalog.list" {
			return "", "", true
		}
		return "inference.endpoints.write", "namespace", true
	case "git":
		return readWritePermission(action, "repo.content.read", "repo.write", "owner")
	case "inference":
		if action == "models.list" {
			return "", "", true
		}
		if strings.HasPrefix(action, "endpoint.") {
			return "inference.endpoints.infer.write", "namespace", true
		}
		return "inference.serverless.write", "", true
	case "job", "scheduled_job", "sandbox":
		return "job.write", "namespace", true
	case "notification":
		if action == "list" {
			return "user.notifications.read", "", true
		}
		if action == "settings.update" {
			return "user.settings.notifications.write", "", true
		}
		return "user.notifications.write", "", true
	case "organization":
		return organizationPermission(action)
	case "paper":
		return "user.papers.write", "", true
	case "provisioning":
		if strings.HasSuffix(action, ".read") || strings.HasSuffix(action, ".list") {
			return "org.serviceAccounts.read", "owner", true
		}
		return "org.serviceAccounts.write", "owner", true
	case "pull_request":
		return "repo.write", "owner", true
	case "repo":
		return repositoryPermission(action)
	case "resource_group":
		return "resourceGroup.write", "owner", true
	case "scim":
		if readAction(action) {
			return "org.members.read", "owner", true
		}
		return "org.members.write", "owner", true
	case "service_account":
		if readAction(action) {
			return "org.serviceAccounts.read", "owner", true
		}
		return "org.serviceAccounts.write", "owner", true
	case "space":
		return readWritePermission(action, "repo.content.read", "repo.write", "owner")
	case "sql_embed":
		return "sql-console.embed.write", "owner", true
	case "user":
		return userPermission(action)
	case "watch":
		return "user.preferences.write", "", true
	case "webhook":
		return readWritePermission(action, "user.webhooks.read", "user.webhooks.write", "owner")
	default:
		return "", "", false
	}
}

func readWritePermission(action, read, write, binding string) (string, string, bool) {
	if readAction(action) {
		return read, binding, true
	}
	return write, binding, true
}

func readAction(action string) bool {
	return action == "list" || action == "read" || action == "exists" || strings.HasSuffix(action, ".list") ||
		strings.HasSuffix(action, ".read") || strings.HasSuffix(action, ".info") || strings.HasSuffix(action, ".verify") ||
		strings.HasSuffix(action, ".connect") || strings.Contains(action, "logs") || strings.Contains(action, "metrics")
}

func organizationPermission(action string) (string, string, bool) {
	switch {
	case action == "audit.export":
		return "org.auditLog.write", "owner", true
	case action == "billing.read":
		return "org.billing.read", "owner", true
	case strings.HasPrefix(action, "member."):
		return readWritePermission(action, "org.members.read", "org.members.write", "owner")
	case strings.HasPrefix(action, "network_security."):
		return readWritePermission(action, "org.networkSecurity.read", "org.networkSecurity.write", "owner")
	case action == "repositories.list":
		return "org.repos.read", "owner", true
	case action == "overview.read":
		return "org.read", "owner", true
	default:
		return "", "", false
	}
}

func repositoryPermission(action string) (string, string, bool) {
	switch {
	case action == "access.request.list" || action == "access.report.export":
		return "repo.access.read", "owner", true
	case strings.HasPrefix(action, "access."):
		return "repo.write", "owner", true
	case readAction(action) || strings.Contains(action, "metadata") || strings.Contains(action, "checksums") || strings.Contains(action, "snapshot") || strings.Contains(action, "notebook") || strings.Contains(action, "commits") || strings.Contains(action, "refs") || strings.Contains(action, "lfs.list"):
		return "repo.content.read", "owner", true
	default:
		return "repo.write", "owner", true
	}
}

func userPermission(action string) (string, string, bool) {
	switch action {
	case "billing.read":
		return "user.billing.read", "", true
	case "likes.read":
		return "user.social.likes.write", "", true
	case "repo.unlike":
		return "user.social.likes.write", "", true
	case "mcp_tools.read":
		return "user.mcp.read", "", true
	case "overview.read":
		return "", "", true
	default:
		return "", "", false
	}
}
