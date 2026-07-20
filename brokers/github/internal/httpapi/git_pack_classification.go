package httpapi

import (
	"bytes"
	"context"
	"math"
	"strings"

	"github.com/osolmaz/brokerkit/git/protocol"
)

const (
	maxGitHubPushObjects     = 1_000_000
	maxGitHubPushObjectBytes = 64 << 20
)

func receivePackProvesFastForward(ctx context.Context, oldOID, newOID string, pack []byte, maxPackBytes int64) bool {
	if len(oldOID) != 40 || len(newOID) != 40 || len(pack) < 4 || !bytes.Equal(pack[:4], []byte("PACK")) {
		return false
	}
	limits := githubPushPackLimits(maxPackBytes)
	objects, err := gitx.ExtractCommitAndTagObjects(ctx, pack, limits, nil)
	if err != nil {
		return false
	}
	parents := make(map[string][]string, len(objects))
	for _, object := range objects {
		if object.Type == "commit" {
			parents[object.Hash] = commitParents(object.Data)
		}
	}
	return commitGraphContains(parents, newOID, oldOID)
}

func githubPushPackLimits(maxPackBytes int64) gitx.PackLimits {
	if maxPackBytes <= 0 {
		maxPackBytes = 25 << 20
	}
	inflated := maxPackBytes * 8
	if maxPackBytes > math.MaxInt64/8 {
		inflated = math.MaxInt64
	}
	return gitx.PackLimits{
		MaxPackBytes: maxPackBytes, MaxObjects: maxGitHubPushObjects,
		MaxObjectBytes: min(maxPackBytes, maxGitHubPushObjectBytes), MaxInflatedBytes: inflated,
	}
}

func commitParents(data []byte) []string {
	var parents []string
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			break
		}
		parent, found := strings.CutPrefix(line, "parent ")
		if found && len(parent) == 40 && isHexObjectID(parent) {
			parents = append(parents, parent)
		}
	}
	return parents
}

func commitGraphContains(parents map[string][]string, start, wanted string) bool {
	pending := []string{start}
	seen := make(map[string]bool, len(parents))
	for len(pending) > 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if current == wanted {
			return true
		}
		if seen[current] {
			continue
		}
		seen[current] = true
		pending = append(pending, parents[current]...)
	}
	return false
}

func isHexObjectID(value string) bool {
	for _, char := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF", char) {
			return false
		}
	}
	return true
}
