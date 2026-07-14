// Package mcpprojection owns GitHub canonical-to-MCP field aliases.
package mcpprojection

import (
	"encoding/json"

	"github.com/osolmaz/brokerkit/capability"
)

var (
	cacheIdentifier = capability.MustProjection(capability.FieldProjection{Canonical: "/key", MCP: "/cache_identifier"})
	documentName    = capability.MustProjection(capability.FieldProjection{Canonical: "/key", MCP: "/document_name"})
	publicMaterial  = capability.MustProjection(capability.FieldProjection{Canonical: "/input/key", MCP: "/input/public_material"})
	armoredMaterial = capability.MustProjection(capability.FieldProjection{Canonical: "/input/armored_public_key", MCP: "/input/armored_public_material"})
	commitSignature = capability.MustProjection(capability.FieldProjection{Canonical: "/input/signature", MCP: "/input/commit_signature"})
	hideSensitive   = capability.MustProjection(capability.FieldProjection{Canonical: "/hide_secret", MCP: "/hide_sensitive_value"})
	transferID      = capability.MustProjection(capability.FieldProjection{Canonical: "/stream/request_key", MCP: "/stream/transfer_id"})
)

var streamResults = map[string]bool{
	"action_run.actions_download_job_logs_for_workflow_run":   true,
	"action_run.actions_download_workflow_run_attempt_logs":   true,
	"action_run.actions_download_workflow_run_logs":           true,
	"artifact.actions_download_artifact":                      true,
	"migration.migrations_get_archive_for_authenticated_user": true,
	"organization.migrations_download_archive_for_org":        true,
	"release.repos_get_release_asset":                         true,
	"repo.download_tarball_archive":                           true,
	"repo.download_zipball_archive":                           true,
}

func ForOperation(descriptor capability.Descriptor) capability.SurfaceProjection {
	projection := capability.SurfaceProjection{}
	switch descriptor.Name {
	case "cache.actions_delete_actions_cache_by_key", "cache.actions_get_actions_cache_list":
		projection.Arguments = cacheIdentifier
	case "repo.read_code_of_conduct", "repo.read_license":
		projection.Arguments = documentName
	case "member.users_create_public_ssh_key_for_authenticated_user", "member.users_create_ssh_signing_key_for_authenticated_user":
		projection.Arguments = publicMaterial
	case "member.users_create_gpg_key_for_authenticated_user":
		projection.Arguments = armoredMaterial
	case "commit.git_create_commit":
		projection.Arguments = commitSignature
	case "secret_scanning.secret_scanning_get_alert", "secret_scanning.secret_scanning_list_alerts_for_org", "secret_scanning.secret_scanning_list_alerts_for_repo":
		projection.Arguments = hideSensitive
	}
	if streamResults[descriptor.Name] {
		projection.Result = transferID
	}
	return projection
}

func ArgumentsToCanonical(descriptor capability.Descriptor, raw json.RawMessage) (json.RawMessage, error) {
	projection := ForOperation(descriptor).Arguments
	if projection.Empty() {
		return raw, nil
	}
	return projection.ToCanonical(raw)
}

func ResultToMCP(operation string, raw json.RawMessage) (json.RawMessage, error) {
	projection := ForOperation(capability.Descriptor{Name: operation}).Result
	if projection.Empty() {
		return raw, nil
	}
	return projection.ToMCP(raw)
}
