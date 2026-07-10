package doctor

type aclState int

const (
	aclAbsent aclState = iota
	aclPresent
	aclUnknown
)
