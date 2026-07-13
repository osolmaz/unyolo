// Package httpapi exposes the broker HTTP surface.
package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
)

func (s *Server) upstreamRequestURL(r *http.Request, rt route) string {
	u := *s.upstream
	u.Path = joinURLPath(s.upstream.Path, upstreamRepoPath(rt)+"/"+rt.tail)
	u.RawQuery = r.URL.RawQuery
	return u.String()
}

func (s *Server) upstreamRepoURL(rt route) string {
	u := *s.upstream
	u.Path = joinURLPath(s.upstream.Path, upstreamRepoPath(rt))
	u.RawQuery = ""
	return u.String()
}

func upstreamRepoPath(rt route) string {
	var repoPath string
	switch rt.repoType {
	case policy.TypeDataset:
		repoPath = "/datasets/" + rt.owner + "/" + rt.name + ".git"
	case policy.TypeSpace:
		repoPath = "/spaces/" + rt.owner + "/" + rt.name + ".git"
	default:
		repoPath = "/" + rt.owner + "/" + rt.name + ".git"
	}
	return repoPath
}

func joinURLPath(basePath, requestPath string) string {
	return strings.TrimRight(basePath, "/") + "/" + strings.TrimLeft(requestPath, "/")
}

func copyForwardHeaders(dst, src http.Header) {
	copyHeaders(dst, src, skipRequestHeader)
}

func copyResponseHeaders(dst, src http.Header) {
	copyHeaders(dst, src, skipResponseHeader)
}

func copyHeaders(dst, src http.Header, skip func(string) bool) {
	for key, values := range src {
		if skip(key) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func skipRequestHeader(key string) bool {
	switch strings.ToLower(key) {
	case "accept-encoding", "authorization", "proxy-authorization", "cookie", "connection", "proxy-connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func skipResponseHeader(key string) bool {
	switch strings.ToLower(key) {
	case "connection", "proxy-connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade", "set-cookie", "set-cookie2":
		return true
	default:
		return false
	}
}

func writePlain(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(message))
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
