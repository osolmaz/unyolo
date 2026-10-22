package httpapi

import (
	"strings"

	"github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
)

func grantRefMatchesOperation(operation policy.Operation, ref string) bool {
	switch operation {
	case policy.OpGitPushAppend:
		return !isReplaceRef(ref)
	case policy.OpGitPushForce, policy.OpGitRefDelete:
		return !isTagRef(ref) && !isReplaceRef(ref)
	case policy.OpGitTagUpdate:
		return isTagRef(ref)
	default:
		return false
	}
}

func parseGrantTarget(target string) (route, bool) {
	parts := strings.Split(target, "/")
	if len(parts) != 3 || strings.Contains(target, "..") {
		return route{}, false
	}
	repoType, ok := grantRepoType(parts[0])
	if !ok || invalidGrantTargetSegment(parts[1]) || invalidGrantTargetSegment(parts[2]) {
		return route{}, false
	}
	return route{repoType: repoType, owner: parts[1], name: parts[2]}, true
}

func grantRepoType(value string) (policy.RepoType, bool) {
	switch value {
	case string(policy.TypeModel):
		return policy.TypeModel, true
	case string(policy.TypeDataset):
		return policy.TypeDataset, true
	case string(policy.TypeSpace):
		return policy.TypeSpace, true
	default:
		return "", false
	}
}

func invalidGrantTargetSegment(value string) bool {
	return value == "" || strings.ContainsAny(value, " \t\r\n/\x00*?")
}
