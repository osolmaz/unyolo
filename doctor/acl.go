package doctor

type aclState int

const (
	aclAbsent aclState = iota
	aclPresent
	aclUnknown
)

// ACLState describes whether an access-control list grants relevant access.
type ACLState = aclState

const (
	ACLAbsent  = aclAbsent
	ACLPresent = aclPresent
	ACLUnknown = aclUnknown
)

// ACLPathKind identifies which access is dangerous for an ACL candidate.
type ACLPathKind int

const (
	ACLFileEntry ACLPathKind = iota
	ACLSocketEntry
	ACLParentDirectory
)

// ACLPath is one path and access class to inspect.
type ACLPath struct {
	Path string
	Kind ACLPathKind
}

// PathACLState reports whether a path has an ACL relevant to mode-bit checks.
func PathACLState(path string) ACLState { return pathACLState(path) }
