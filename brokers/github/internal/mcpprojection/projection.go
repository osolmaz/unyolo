// Package mcpprojection owns GitHub canonical-to-MCP field aliases.
package mcpprojection

import (
	"encoding/json"

	"github.com/osolmaz/brokerkit/operation/capability"
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

var argumentProjections = map[string]capability.Projection{
	"cache.actions_delete_actions_cache_by_key":                  cacheIdentifier,
	"cache.actions_get_actions_cache_list":                       cacheIdentifier,
	"repo.read_code_of_conduct":                                  documentName,
	"repo.read_license":                                          documentName,
	"member.users_create_public_ssh_key_for_authenticated_user":  publicMaterial,
	"member.users_create_ssh_signing_key_for_authenticated_user": publicMaterial,
	"repo.create_deploy_key":                                     publicMaterial,
	"member.users_create_gpg_key_for_authenticated_user":         armoredMaterial,
	"commit.git_create_commit":                                   commitSignature,
	"secret_scanning.secret_scanning_get_alert":                  hideSensitive,
	"secret_scanning.secret_scanning_list_alerts_for_org":        hideSensitive,
	"secret_scanning.secret_scanning_list_alerts_for_repo":       hideSensitive,
}

func ForOperation(descriptor capability.Descriptor) capability.SurfaceProjection {
	projection := capability.SurfaceProjection{Arguments: argumentProjections[descriptor.Name]}
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
