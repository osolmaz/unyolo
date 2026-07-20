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

type receivePackGraph struct {
	parents map[string][]string
	valid   bool
	failure string
}

func (s *Server) receivePackGraphForRepo(ctx context.Context, owner, repo string, pack []byte) receivePackGraph {
	graph := inspectReceivePackGraph(ctx, pack, s.maxReceivePackBytes, s.githubPackBaseReader(owner, repo))
	if graph.failure != "" {
		s.logger.Warn("could not inspect Git push pack", "error", graph.failure)
	}
	return graph
}

func inspectReceivePackGraph(ctx context.Context, pack []byte, maxPackBytes int64, readBase gitx.PackBaseReader) receivePackGraph {
	if len(pack) < 4 || !bytes.Equal(pack[:4], []byte("PACK")) {
		return receivePackGraph{}
	}
	limits := githubPushPackLimits(maxPackBytes)
	objects, err := gitx.ExtractCommitAndTagObjects(ctx, pack, limits, readBase)
	if err != nil {
		return receivePackGraph{failure: err.Error()}
	}
	parents := make(map[string][]string, len(objects))
	for _, object := range objects {
		if object.Type == "commit" {
			parents[object.Hash] = commitParents(object.Data)
		}
	}
	return receivePackGraph{parents: parents, valid: true}
}

func (graph receivePackGraph) provesFastForward(oldOID, newOID string) bool {
	return graph.valid && len(oldOID) == 40 && len(newOID) == 40 && commitGraphContains(graph.parents, newOID, oldOID)
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
