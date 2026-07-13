package gitproxy

import (
	"context"

	"github.com/osolmaz/brokerkit/gitx"
)

const (
	maxInspectedPackBytes    = 25 * 1024 * 1024
	maxStoredPackObjectBytes = 16 * 1024 * 1024
	maxParsedPackObjects     = 1 << 20
	maxInflatedPackBytes     = 128 * 1024 * 1024
)

// GitObject is a commit or tag object extracted from an incoming pack.
type GitObject struct {
	Type string
	Data []byte
	SHA  string
}

// BaseObjectReader reads an existing object by SHA from the mirror.
type BaseObjectReader func(string) (GitObject, bool, error)

// ExtractCommitAndTagObjects extracts bounded commit and tag objects through
// BrokerKit's shared go-git adapter.
func ExtractCommitAndTagObjects(
	ctx context.Context,
	pack []byte,
	readBase BaseObjectReader,
) ([]GitObject, error) {
	var sharedReader gitx.PackBaseReader
	if readBase != nil {
		sharedReader = func(_ context.Context, hash string) (gitx.PackObject, bool, error) {
			object, found, err := readBase(hash)
			return gitx.PackObject{Type: object.Type, Data: object.Data, Hash: object.SHA}, found, err
		}
	}
	objects, err := gitx.ExtractCommitAndTagObjects(ctx, pack, gitx.PackLimits{
		MaxPackBytes:     maxInspectedPackBytes,
		MaxObjects:       maxParsedPackObjects,
		MaxObjectBytes:   maxStoredPackObjectBytes,
		MaxInflatedBytes: maxInflatedPackBytes,
	}, sharedReader)
	if err != nil {
		return nil, err
	}
	extracted := make([]GitObject, len(objects))
	for index, object := range objects {
		extracted[index] = GitObject{Type: object.Type, Data: object.Data, SHA: object.Hash}
	}
	return extracted, nil
}
