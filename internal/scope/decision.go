package scope

// Operation is a broker operation class, used both for policy decisions
// and audit lines.
type Operation string

// Repo operation classes for the git proxy.
const (
	OpGitFetch    Operation = "git_upload_pack"
	OpGitPush     Operation = "git_receive_pack"
	OpLFSDownload Operation = "lfs_download"
	OpLFSUpload   Operation = "lfs_upload"
)

// Grant operation classes for dangerous git updates.
const (
	OpGitHistoryRewrite Operation = "git_history_rewrite"
	OpGitRefDelete      Operation = "git_ref_delete"
	OpGitTagUpdate      Operation = "git_tag_update"
)

// Decision is an allow/refuse outcome with a human-readable reason.
type Decision struct {
	Allowed bool
	Reason  string
}

// DecideRepo classifies op against the configured scope for the repo
// identified by (t, owner, name). Unknown operations are refused: the
// engine fails closed.
func (s Scope) DecideRepo(t RepoType, owner, name string, op Operation) Decision {
	repo, ok := s.Repo(t, owner, name)
	if !ok {
		return Decision{Allowed: false, Reason: "repository is not in scope"}
	}
	switch op {
	case OpGitFetch, OpLFSDownload:
		return Decision{Allowed: true}
	case OpGitPush, OpLFSUpload:
		if repo.Mode != ModeAppendOnly {
			return Decision{Allowed: false, Reason: "repository is read-only"}
		}
		return Decision{Allowed: true}
	default:
		return Decision{Allowed: false, Reason: "operation is not supported"}
	}
}
