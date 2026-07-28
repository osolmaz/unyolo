package mcpprojection

import (
	"testing"

	"github.com/osolmaz/unyolo/brokers/github/internal/opcatalog"
)

func TestRequiredProjectionRegistry(t *testing.T) {
	for _, operation := range []string{
		"cache.actions_delete_actions_cache_by_key", "repo.read_license",
		"member.users_create_public_ssh_key_for_authenticated_user", "member.users_create_gpg_key_for_authenticated_user",
		"repo.create_deploy_key",
		"commit.git_create_commit", "secret_scanning.secret_scanning_get_alert",
		"artifact.actions_download_artifact",
	} {
		descriptor, found := opcatalog.ByName(operation)
		if !found {
			t.Fatalf("missing operation %s", operation)
		}
		projection := ForOperation(descriptor.Descriptor)
		if projection.Arguments.Empty() && projection.Result.Empty() {
			t.Fatalf("operation %s has no projection", operation)
		}
	}
}
