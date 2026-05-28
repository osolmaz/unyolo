package githubaccess

import "strings"

type Operation string

const (
	OperationCreatePullRequest Operation = "create_pull_request"
	OperationPushBranch        Operation = "push_branch"
	OperationForcePushBranch   Operation = "force_push_branch"
)

type DecisionInput struct {
	Operation   Operation
	Repository  RepositoryRef
	TargetOwner string
}

type Decision struct {
	Allowed bool
	Reason  string
}

func (c Config) Decide(input DecisionInput) Decision {
	repository := RepositoryRef{
		Owner: strings.TrimSpace(input.Repository.Owner),
		Name:  strings.TrimSpace(input.Repository.Name),
	}
	targetOwner := strings.TrimSpace(input.TargetOwner)

	switch input.Operation {
	case OperationCreatePullRequest:
		if c.Allows(repository.Owner, repository.Name) {
			return allow("repository is in scope")
		}
		return deny("repository is not in scope")
	case OperationPushBranch, OperationForcePushBranch:
		if c.allowsTargetOwner(repository, targetOwner) {
			return allow("target owner is in scope")
		}
		return deny("target owner is not in scope")
	default:
		return deny("operation is not supported")
	}
}

func (c Config) allowsTargetOwner(repository RepositoryRef, targetOwner string) bool {
	if targetOwner == "" {
		return false
	}
	if c.AllowsOwner(targetOwner) {
		return true
	}
	return targetOwner == repository.Owner && c.Allows(repository.Owner, repository.Name)
}

func (c Config) AllowsOwner(owner string) bool {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return false
	}
	for _, allowedOwner := range normalizeOwners(c.Owners) {
		if owner == allowedOwner {
			return true
		}
	}
	return false
}

func allow(reason string) Decision {
	return Decision{Allowed: true, Reason: reason}
}

func deny(reason string) Decision {
	return Decision{Allowed: false, Reason: reason}
}
