package httpapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/osolmaz/unyolo/brokers/github/internal/githubauth"
	"github.com/osolmaz/unyolo/brokers/github/internal/policy"
	gitx "github.com/osolmaz/unyolo/git/protocol"
	"github.com/osolmaz/unyolo/internal/strictjson"
	httpx "github.com/osolmaz/unyolo/transport/http"
)

const githubPackBaseResponseLimit = maxGitHubPushObjectBytes

func (s *Server) githubPackBaseReader(owner, repo string) gitx.PackBaseReader {
	var once sync.Once
	var credential *githubauth.Credential
	var credentialErr error
	return func(ctx context.Context, oid string) (gitx.PackObject, bool, error) {
		once.Do(func() {
			credential, credentialErr = s.githubCredentialForRepoContext(ctx, string(policy.OperationGitFetch), owner, repo)
		})
		if credentialErr != nil {
			return gitx.PackObject{}, false, errors.New("acquire GitHub pack-base credential")
		}
		return s.readGitHubPackBase(ctx, credential, owner, repo, oid)
	}
}

func (s *Server) readGitHubPackBase(ctx context.Context, credential *githubauth.Credential, owner, repo, oid string) (gitx.PackObject, bool, error) {
	blob, found, err := s.readGitHubPackBaseResponse(ctx, credential, owner, repo, "blobs", oid, "application/vnd.github.raw+json")
	if err != nil {
		return gitx.PackObject{}, false, err
	}
	if found {
		return verifiedGitHubPackBase("blob", oid, blob)
	}
	treeJSON, found, err := s.readGitHubPackBaseResponse(ctx, credential, owner, repo, "trees", oid, "application/vnd.github+json")
	if err != nil || !found {
		return gitx.PackObject{}, false, err
	}
	tree, err := githubTreeObject(treeJSON, oid)
	if err != nil {
		return gitx.PackObject{}, false, err
	}
	return verifiedGitHubPackBase("tree", oid, tree)
}

func (s *Server) readGitHubPackBaseResponse(
	ctx context.Context,
	credential *githubauth.Credential,
	owner, repo, kind, oid, accept string,
) ([]byte, bool, error) {
	upstream := s.githubAPIBaseURL.JoinPath("repos", owner, repo, "git", kind, oid)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, upstream.String(), http.NoBody)
	if err != nil {
		return nil, false, errors.New("create GitHub pack-base request")
	}
	if err := credential.AuthorizeAPI(request); err != nil {
		return nil, false, errors.New("authorize GitHub pack-base request")
	}
	request.Header.Set("Accept", accept)
	response, err := s.githubClient.Do(request)
	if err != nil {
		return nil, false, errors.New("fetch GitHub pack base")
	}
	defer func() { _ = response.Body.Close() }()
	found, err := githubPackBaseFound(response.StatusCode)
	if err != nil {
		return nil, false, err
	}
	if !found {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil, false, nil
	}
	body, err := httpx.ReadLimited(response.Body, githubPackBaseResponseLimit)
	if err != nil {
		return nil, false, errors.New("fetch GitHub pack base: response exceeds limit")
	}
	return body, true, nil
}

func githubPackBaseFound(status int) (bool, error) {
	switch {
	case status == http.StatusNotFound || status == http.StatusUnprocessableEntity:
		return false, nil
	case status < http.StatusOK || status >= http.StatusMultipleChoices:
		return false, fmt.Errorf("fetch GitHub pack base: upstream returned %d", status)
	default:
		return true, nil
	}
}

func verifiedGitHubPackBase(objectType, oid string, data []byte) (gitx.PackObject, bool, error) {
	hash, err := gitx.ComputeObjectHash(objectType, data)
	if err != nil || !strings.EqualFold(hash, oid) {
		return gitx.PackObject{}, false, errors.New("GitHub pack base failed object verification")
	}
	return gitx.PackObject{Type: objectType, Data: data, Hash: hash}, true, nil
}

type githubTreePayload struct {
	SHA       string            `json:"sha"`
	Truncated bool              `json:"truncated"`
	Tree      []githubTreeEntry `json:"tree"`
}

type githubTreeEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	SHA  string `json:"sha"`
}

func githubTreeObject(data []byte, oid string) ([]byte, error) {
	payload, err := decodeGitHubTreePayload(data, oid)
	if err != nil {
		return nil, err
	}
	var tree bytes.Buffer
	for _, entry := range payload.Tree {
		if err := appendGitHubTreeEntry(&tree, entry); err != nil {
			return nil, err
		}
	}
	return tree.Bytes(), nil
}

func decodeGitHubTreePayload(data []byte, oid string) (githubTreePayload, error) {
	var payload githubTreePayload
	if err := strictjson.Decode(data, &payload, false); err != nil || payload.Truncated || !strings.EqualFold(payload.SHA, oid) {
		return githubTreePayload{}, errors.New("invalid GitHub tree response")
	}
	return payload, nil
}

func appendGitHubTreeEntry(tree *bytes.Buffer, entry githubTreeEntry) error {
	mode, err := strconv.ParseUint(entry.Mode, 8, 32)
	if err != nil || !validGitTreeMode(mode) {
		return errors.New("invalid GitHub tree entry")
	}
	if entry.Path == "" || strings.ContainsAny(entry.Path, "\x00/") {
		return errors.New("invalid GitHub tree entry")
	}
	hash, err := hex.DecodeString(entry.SHA)
	if err != nil || len(hash) != 20 {
		return errors.New("invalid GitHub tree object id")
	}
	_, _ = fmt.Fprintf(tree, "%o %s", mode, entry.Path)
	_ = tree.WriteByte(0)
	_, _ = tree.Write(hash)
	return nil
}

func validGitTreeMode(mode uint64) bool {
	switch mode {
	case 0o40000, 0o100644, 0o100664, 0o100755, 0o120000, 0o160000:
		return true
	default:
		return false
	}
}
