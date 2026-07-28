// Package httpapi exposes the broker HTTP surface.
package httpapi

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
)

func (s *Server) classify(r *http.Request) (classifiedRequest, int, string) {
	rt, ok := parseRepoRoute(r.URL.Path)
	if !ok {
		return classifiedRequest{}, http.StatusForbidden, "request is outside configured git routes"
	}
	op, body, bodyRead, status, reason := classifyOperation(r, rt)
	if reason != "" {
		return classifiedRequest{}, status, reason
	}
	return classifiedRequest{route: rt, operation: op, attrs: maxBytesAttrsForRequest(r, body, bodyRead), body: body, bodyRead: bodyRead}, 0, ""
}

func parseRepoRoute(requestPath string) (route, bool) {
	trimmed := strings.TrimPrefix(requestPath, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return route{}, false
	}
	repoType, prefixOffset := routePrefix(parts[0])
	if len(parts) < prefixOffset+3 {
		return route{}, false
	}
	owner := parts[prefixOffset]
	name := strings.TrimSuffix(parts[prefixOffset+1], ".git")
	tail := strings.Join(parts[prefixOffset+2:], "/")
	if owner == "" || name == "" || tail == "" {
		return route{}, false
	}
	return route{repoType: repoType, owner: owner, name: name, tail: tail}, true
}

func routePrefix(firstSegment string) (policy.RepoType, int) {
	switch firstSegment {
	case "datasets":
		return policy.TypeDataset, 1
	case "spaces":
		return policy.TypeSpace, 1
	default:
		return policy.TypeModel, 0
	}
}

func classifyOperation(r *http.Request, rt route) (policy.Operation, []byte, bool, int, string) {
	switch {
	case r.Method == http.MethodGet && rt.tail == "info/refs":
		return classifyInfoRefs(r.URL.Query().Get("service"))
	case strings.HasPrefix(rt.tail, "info/lfs/"):
		return classifyLFS(r, rt.tail)
	case r.Method == http.MethodPost:
		return classifyGitPost(rt.tail)
	default:
		return "", nil, false, http.StatusForbidden, "unsupported git route"
	}
}

func classifyInfoRefs(service string) (policy.Operation, []byte, bool, int, string) {
	return classifyGitService(service, "unsupported git service")
}

func classifyGitPost(tail string) (policy.Operation, []byte, bool, int, string) {
	return classifyGitService(tail, "unsupported git route")
}

func classifyGitService(value, unsupported string) (policy.Operation, []byte, bool, int, string) {
	switch value {
	case "git-upload-pack":
		return policy.OpGitFetch, nil, false, 0, ""
	case "git-receive-pack":
		return policy.OpGitPushAppend, nil, false, 0, ""
	default:
		return "", nil, false, http.StatusForbidden, unsupported
	}
}

func classifyLFS(r *http.Request, tail string) (policy.Operation, []byte, bool, int, string) {
	if r.Method == http.MethodPost && tail == "info/lfs/objects/batch" {
		return classifyLFSBatch(r)
	}
	if r.Method == http.MethodPost && tail == "info/lfs/locks/verify" {
		return policy.OpRepoContentsRead, nil, false, 0, ""
	}
	if isLFSObjectDownload(r.Method, tail) {
		return policy.OpRepoContentsRead, nil, false, 0, ""
	}
	if isLFSObjectUpload(r.Method, tail) {
		return policy.OpGitPushAppend, nil, false, 0, ""
	}
	return "", nil, false, http.StatusForbidden, "unsupported LFS route"
}

func classifyLFSBatch(r *http.Request) (policy.Operation, []byte, bool, int, string) {
	body, tooLarge, err := readLimited(r.Body, maxLFSBatchBytes)
	if err != nil {
		return "", nil, false, http.StatusBadRequest, "could not read LFS batch request"
	}
	if tooLarge {
		return "", nil, false, http.StatusRequestEntityTooLarge, "LFS batch request is too large"
	}
	var payload struct {
		Operation string `json:"operation"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", nil, false, http.StatusBadRequest, "could not parse LFS batch request"
	}
	return classifyLFSOperation(payload.Operation, body)
}

func classifyLFSOperation(operation string, body []byte) (policy.Operation, []byte, bool, int, string) {
	switch operation {
	case "download":
		return policy.OpRepoContentsRead, body, true, 0, ""
	case "upload":
		return policy.OpGitPushAppend, body, true, 0, ""
	default:
		return "", nil, false, http.StatusForbidden, "unsupported LFS operation"
	}
}

func isLFSObjectDownload(method, tail string) bool {
	if method != http.MethodGet && method != http.MethodHead {
		return false
	}
	oid, ok := strings.CutPrefix(tail, "info/lfs/objects/")
	return ok && isLFSOID(oid)
}

func isLFSObjectUpload(method, tail string) bool {
	rest, ok := strings.CutPrefix(tail, "info/lfs/objects/")
	if !ok {
		return false
	}
	switch method {
	case http.MethodPost:
		return isLFSObjectVerify(rest)
	case http.MethodPut, http.MethodPatch:
		return isLFSObjectBodyUpload(rest)
	default:
		return false
	}
}

func isLFSObjectVerify(rest string) bool {
	oid, ok := strings.CutSuffix(rest, "/verify")
	return ok && isLFSOID(oid)
}

func isLFSObjectBodyUpload(rest string) bool {
	oid, size, ok := strings.Cut(rest, "/")
	return ok && isLFSOID(oid) && isDecimal(size)
}

func isLFSOID(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func isDecimal(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
