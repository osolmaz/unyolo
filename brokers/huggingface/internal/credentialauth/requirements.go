package credentialauth

import (
	"strings"

	"github.com/osolmaz/brokerkit/credential/provider"
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
	if fixed, ok := fixedFamilyPermissions[family]; ok {
		return fixed.permission, fixed.binding, true
	}
	resolver, ok := familyPermissionResolvers[family]
	if !ok {
		return "", "", false
	}
	return resolver(action)
}

type permissionRule struct {
	permission string
	binding    string
}

type permissionResolver func(string) (string, string, bool)

var fixedFamilyPermissions = map[string]permissionRule{
	"auth": {}, "identity": {}, "catalog": {},
	"dataset": {permission: "repo.content.read", binding: "owner"},
	"job":     {permission: "job.write", binding: "namespace"}, "scheduled_job": {permission: "job.write", binding: "namespace"},
	"sandbox": {permission: "job.write", binding: "namespace"},
	"paper":   {permission: "user.papers.write"}, "pull_request": {permission: "repo.write", binding: "owner"},
	"resource_group": {permission: "resourceGroup.write", binding: "owner"},
	"sql_embed":      {permission: "sql-console.embed.write", binding: "owner"}, "watch": {permission: "user.preferences.write"},
}

var familyPermissionResolvers = map[string]permissionResolver{
	"bucket": func(action string) (string, string, bool) {
		return readWritePermission(action, "repo.content.read", "repo.write", "namespace")
	},
	"collection": func(action string) (string, string, bool) {
		return readWritePermission(action, "collection.read", "collection.write", "owner")
	},
	"discussion": discussionPermission, "endpoint": endpointPermission,
	"git": func(action string) (string, string, bool) {
		return readWritePermission(action, "repo.content.read", "repo.write", "owner")
	},
	"inference": inferencePermission, "notification": notificationPermission, "organization": organizationPermission,
	"provisioning": provisioningPermission, "repo": repositoryPermission,
	"scim": func(action string) (string, string, bool) {
		return readWritePermission(action, "org.members.read", "org.members.write", "owner")
	},
	"service_account": func(action string) (string, string, bool) {
		return readWritePermission(action, "org.serviceAccounts.read", "org.serviceAccounts.write", "owner")
	},
	"space": func(action string) (string, string, bool) {
		return readWritePermission(action, "repo.content.read", "repo.write", "owner")
	},
	"user": userPermission,
	"webhook": func(action string) (string, string, bool) {
		return readWritePermission(action, "user.webhooks.read", "user.webhooks.write", "owner")
	},
}

func discussionPermission(action string) (string, string, bool) {
	if readAction(action) {
		return "repo.content.read", "owner", true
	}
	return "discussion.write", "owner", true
}

func endpointPermission(action string) (string, string, bool) {
	if action == "catalog.list" {
		return "", "", true
	}
	return "inference.endpoints.write", "namespace", true
}

func inferencePermission(action string) (string, string, bool) {
	if action == "models.list" {
		return "", "", true
	}
	if strings.HasPrefix(action, "endpoint.") {
		return "inference.endpoints.infer.write", "namespace", true
	}
	return "inference.serverless.write", "", true
}

func notificationPermission(action string) (string, string, bool) {
	switch action {
	case "list":
		return "user.notifications.read", "", true
	case "settings.update":
		return "user.settings.notifications.write", "", true
	default:
		return "user.notifications.write", "", true
	}
}

func provisioningPermission(action string) (string, string, bool) {
	return readWritePermission(action, "org.serviceAccounts.read", "org.serviceAccounts.write", "owner")
}

func readWritePermission(action, read, write, binding string) (string, string, bool) {
	if readAction(action) {
		return read, binding, true
	}
	return write, binding, true
}

func readAction(action string) bool {
	if action == "list" || action == "read" || action == "exists" {
		return true
	}
	for _, suffix := range []string{".list", ".read", ".info", ".verify", ".connect"} {
		if strings.HasSuffix(action, suffix) {
			return true
		}
	}
	return strings.Contains(action, "logs") || strings.Contains(action, "metrics")
}

func organizationPermission(action string) (string, string, bool) {
	if fixed, ok := organizationFixedPermissions[action]; ok {
		return fixed.permission, fixed.binding, true
	}
	if strings.HasPrefix(action, "member.") {
		return readWritePermission(action, "org.members.read", "org.members.write", "owner")
	}
	if strings.HasPrefix(action, "network_security.") {
		return readWritePermission(action, "org.networkSecurity.read", "org.networkSecurity.write", "owner")
	}
	return "", "", false
}

var organizationFixedPermissions = map[string]permissionRule{
	"audit.export":      {permission: "org.auditLog.write", binding: "owner"},
	"billing.read":      {permission: "org.billing.read", binding: "owner"},
	"repositories.list": {permission: "org.repos.read", binding: "owner"},
	"overview.read":     {permission: "org.read", binding: "owner"},
}

func repositoryPermission(action string) (string, string, bool) {
	switch {
	case action == "access.request.list" || action == "access.report.export":
		return "repo.access.read", "owner", true
	case strings.HasPrefix(action, "access."):
		return "repo.write", "owner", true
	case repositoryReadAction(action):
		return "repo.content.read", "owner", true
	default:
		return "repo.write", "owner", true
	}
}

func repositoryReadAction(action string) bool {
	if readAction(action) {
		return true
	}
	for _, marker := range []string{"metadata", "checksums", "snapshot", "notebook", "commits", "refs", "lfs.list"} {
		if strings.Contains(action, marker) {
			return true
		}
	}
	return false
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
