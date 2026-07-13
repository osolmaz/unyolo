//go:build linux || darwin

package isolation

import "os"

type identity struct {
	user          string
	uid           int
	gid           int
	gidSet        bool
	gids          map[int]bool
	groups        map[string]bool
	groupsUnknown bool
	pid           int
}

type fileStat struct {
	path string
	mode os.FileMode
	uid  int
	gid  int
}

type parentFailure int

const (
	parentWritable parentFailure = iota
	parentSymlinkReplace
)

type pathKind int

const (
	pathKindTokenFile pathKind = iota
	pathKindSocket
)

type pathMessageSet struct {
	entryLabel     string
	resolveUnknown string
	parentPass     string
}

var pathMessages = map[pathKind]pathMessageSet{
	pathKindTokenFile: {
		entryLabel:     "token-file",
		resolveUnknown: "could not resolve token-file path",
		parentPass:     "agent cannot write checked token-file parent directories",
	},
	pathKindSocket: {
		entryLabel:     "socket",
		resolveUnknown: "could not resolve socket path",
		parentPass:     "agent cannot write checked parent directories",
	},
}
