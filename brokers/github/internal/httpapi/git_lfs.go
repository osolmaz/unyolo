package httpapi

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/brokerkit/brokers/github/internal/policy"
	"github.com/osolmaz/brokerkit/brokers/github/internal/security"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/transport/http"
)

const (
	githubLFSActionQuery = "brokerkit_lfs_action"
	githubLFSActionTTL   = time.Hour
	maxGitHubLFSBatch    = 1 << 20
)

type githubLFSAction struct {
	client    string
	owner     string
	repo      string
	operation policy.Operation
	method    string
	path      string
	upstream  *url.URL
	headers   http.Header
	created   time.Time
}

func (s *Server) gitLFSBatch(c echo.Context) error {
	body, err := httpx.ReadLimited(c.Request().Body, maxGitHubLFSBatch)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, httpx.ErrBodyTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		return echo.NewHTTPError(status, "invalid Git LFS batch request")
	}
	var request struct {
		Operation string `json:"operation"`
	}
	if err := strictjson.Decode(body, &request, false); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid Git LFS batch request")
	}
	operation, err := requireGitTransportOperation(request.Operation, "unsupported Git LFS operation")
	if err != nil {
		return err
	}
	c.Request().Body = io.NopCloser(bytes.NewReader(body))
	c.Request().ContentLength = int64(len(body))
	return s.authorizeBrokerRequest(c, s.repoRequest(c, operation, nil), func(c echo.Context) error {
		return s.proxyGitLFSBatch(c, operation)
	})
}

func (s *Server) proxyGitLFSBatch(c echo.Context, operation policy.Operation) error {
	request, err := s.newGitHubLFSRequest(c, s.gitUpstreamURL(c), nil)
	if err != nil {
		return err
	}
	response, err := s.doGitHubLFSRequest(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return s.copyGitHubLFSResponse(c, response, false)
	}
	body, err := httpx.ReadLimited(response.Body, maxGitHubLFSBatch)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "invalid GitHub LFS response")
	}
	var payload map[string]any
	if err := strictjson.Decode(body, &payload, false); err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "invalid GitHub LFS response")
	}
	s.rewriteGitHubLFSActions(c, security.ClientFromContext(c), operation, payload)
	rewritten, err := json.Marshal(payload)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadGateway, "invalid GitHub LFS response")
	}
	httpx.CopyHeaders(c.Response().Header(), response.Header, httpx.DropAny(githubProxyResponseHeader, httpx.RewrittenBodyHeader))
	c.Response().Header().Set("Content-Type", "application/vnd.git-lfs+json")
	c.Response().WriteHeader(response.StatusCode)
	_, err = c.Response().Write(rewritten)
	return err
}

func (s *Server) rewriteGitHubLFSActions(c echo.Context, client string, operation policy.Operation, payload map[string]any) {
	objects, ok := payload["objects"].([]any)
	if !ok {
		return
	}
	for _, raw := range objects {
		s.rewriteGitHubLFSObject(c, client, operation, raw)
	}
}

func (s *Server) rewriteGitHubLFSObject(c echo.Context, client string, operation policy.Operation, raw any) {
	object, ok := raw.(map[string]any)
	if !ok {
		return
	}
	oid, _ := object["oid"].(string)
	size, sizeOK := githubLFSSize(object["size"])
	if !validGitHubLFSOID(oid) || !sizeOK {
		delete(object, "actions")
		return
	}
	actions, ok := object["actions"].(map[string]any)
	if !ok {
		return
	}
	for name, rawAction := range actions {
		action, valid := rawAction.(map[string]any)
		if !valid || !s.rewriteGitHubLFSAction(c, client, operation, oid, size, name, action) {
			delete(actions, name)
		}
	}
}

func (s *Server) rewriteGitHubLFSAction(c echo.Context, client string, operation policy.Operation, oid, size, name string, payload map[string]any) bool {
	action, ok := s.parseGitHubLFSAction(c, client, operation, oid, size, name, payload)
	if !ok {
		return false
	}
	id, err := randomGitHubLFSActionID()
	if err != nil {
		return false
	}
	s.storeGitHubLFSAction(id, action)
	payload["href"] = githubLFSLocalActionURL(c.Request(), action.path, id)
	delete(payload, "header")
	return true
}

func (s *Server) parseGitHubLFSAction(c echo.Context, client string, operation policy.Operation, oid, size, name string, payload map[string]any) (githubLFSAction, bool) {
	href, ok := payload["href"].(string)
	if !ok {
		return githubLFSAction{}, false
	}
	upstream, err := url.Parse(href)
	if err != nil || !s.validGitHubLFSActionURL(upstream) {
		return githubLFSAction{}, false
	}
	method, localPath, ok := githubLFSActionRoute(c, oid, size, name)
	if !ok {
		return githubLFSAction{}, false
	}
	action := githubLFSAction{
		client: client, owner: c.Param("owner"), repo: strings.TrimSuffix(c.Param("repoGit"), ".git"), operation: operation,
		method: method, path: localPath, upstream: upstream, headers: githubLFSHeaders(payload["header"]), created: time.Now().UTC(),
	}
	return action, true
}

func (s *Server) validGitHubLFSActionURL(upstream *url.URL) bool {
	return upstream != nil && (upstream.Scheme == "https" || sameOrigin(upstream, s.githubGitBaseURL)) &&
		upstream.Host != "" && upstream.User == nil && upstream.Fragment == ""
}

func (s *Server) storeGitHubLFSAction(id string, action githubLFSAction) {
	s.lfsMu.Lock()
	s.pruneGitHubLFSActions(time.Now().UTC())
	s.lfsActions[id] = action
	s.lfsMu.Unlock()
}

func githubLFSLocalActionURL(request *http.Request, path, id string) string {
	local := url.URL{Scheme: requestScheme(request), Host: request.Host, Path: path}
	query := local.Query()
	query.Set(githubLFSActionQuery, id)
	local.RawQuery = query.Encode()
	return local.String()
}

func githubLFSActionRoute(c echo.Context, oid, size, name string) (string, string, bool) {
	base := "/" + c.Param("owner") + "/" + c.Param("repoGit") + "/info/lfs/objects/" + oid
	switch name {
	case "download":
		return http.MethodGet, base, true
	case "upload":
		return http.MethodPut, base + "/" + size, true
	case "verify":
		return http.MethodPost, base + "/verify", true
	default:
		return "", "", false
	}
}

func (s *Server) gitLFSAction(c echo.Context) error {
	action, ok := s.authorizedGitHubLFSAction(c)
	if !ok {
		return echo.NewHTTPError(http.StatusForbidden, "Git LFS action is invalid or expired")
	}
	return s.authorizeBrokerRequest(c, s.repoRequest(c, action.operation, nil), func(c echo.Context) error {
		return s.proxyGitHubLFSAction(c, action)
	})
}

func (s *Server) authorizedGitHubLFSAction(c echo.Context) (githubLFSAction, bool) {
	action, ok := s.lookupGitHubLFSAction(c.QueryParam(githubLFSActionQuery))
	if !ok {
		return githubLFSAction{}, false
	}
	repo := strings.TrimSuffix(c.Param("repoGit"), ".git")
	valid := action.client == security.ClientFromContext(c) && action.owner == c.Param("owner") && action.repo == repo &&
		action.path == c.Request().URL.Path && githubLFSMethodMatches(action.method, c.Request().Method)
	return action, valid
}

func (s *Server) proxyGitHubLFSAction(c echo.Context, action githubLFSAction) error {
	request, err := s.newGitHubLFSRequest(c, action.upstream, action.headers)
	if err != nil {
		return err
	}
	response, err := s.doGitHubLFSRequest(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	return s.copyGitHubLFSResponse(c, response, false)
}

func (s *Server) gitLFSDirect(c echo.Context) error {
	operation := policy.OperationGitFetch
	if c.Request().Method == http.MethodPost && !strings.HasSuffix(c.Request().URL.Path, "/locks/verify") {
		operation = policy.OperationGitPushAdvertise
	}
	return s.authorizeBrokerRequest(c, s.repoRequest(c, operation, nil), s.proxyGit)
}

func (s *Server) newGitHubLFSRequest(c echo.Context, upstream *url.URL, headers http.Header) (*http.Request, error) {
	request, err := http.NewRequestWithContext(c.Request().Context(), c.Request().Method, upstream.String(), c.Request().Body)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusBadGateway, "create upstream Git LFS request")
	}
	httpx.CopyHeaders(request.Header, c.Request().Header, httpx.ProxyRequestHeader)
	applyGitHubLFSHeaders(request.Header, headers)
	request.ContentLength = c.Request().ContentLength
	if err := s.authorizeSameOriginGitHubLFS(c, request, upstream); err != nil {
		return nil, err
	}
	return request, nil
}

func applyGitHubLFSHeaders(target, headers http.Header) {
	for key, values := range headers {
		if strings.EqualFold(key, "Host") || strings.EqualFold(key, "Content-Length") {
			continue
		}
		target.Del(key)
		for _, value := range values {
			target.Add(key, value)
		}
	}
}

func (s *Server) authorizeSameOriginGitHubLFS(c echo.Context, request *http.Request, upstream *url.URL) error {
	if request.Header.Get("Authorization") == "" && sameOrigin(upstream, s.githubGitBaseURL) {
		return s.configureGitHubGitRequest(c, request, c.Param("owner"), strings.TrimSuffix(c.Param("repoGit"), ".git"))
	}
	return nil
}

func (s *Server) doGitHubLFSRequest(request *http.Request) (*http.Response, error) {
	if request.URL == nil || (request.URL.Scheme != "http" && request.URL.Scheme != "https") {
		return nil, echo.NewHTTPError(http.StatusBadGateway, "invalid Git LFS action")
	}
	response, err := s.githubGitClient.Do(request) // #nosec G704 -- URL originates in GitHub's authenticated LFS batch response.
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusBadGateway, "upstream Git LFS request failed")
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		_ = response.Body.Close()
		return nil, echo.NewHTTPError(http.StatusBadGateway, "upstream Git LFS redirect refused")
	}
	return response, nil
}

func (s *Server) copyGitHubLFSResponse(c echo.Context, response *http.Response, rewritten bool) error {
	drop := githubProxyResponseHeader
	if rewritten {
		drop = httpx.DropAny(drop, httpx.RewrittenBodyHeader)
	}
	httpx.CopyHeaders(c.Response().Header(), response.Header, drop)
	c.Response().WriteHeader(response.StatusCode)
	_, err := io.Copy(c.Response(), response.Body)
	return err
}

func (s *Server) lookupGitHubLFSAction(id string) (githubLFSAction, bool) {
	if id == "" {
		return githubLFSAction{}, false
	}
	s.lfsMu.Lock()
	defer s.lfsMu.Unlock()
	now := time.Now().UTC()
	s.pruneGitHubLFSActions(now)
	action, ok := s.lfsActions[id]
	return action, ok
}

func (s *Server) pruneGitHubLFSActions(now time.Time) {
	for id, action := range s.lfsActions {
		if now.Sub(action.created) > githubLFSActionTTL {
			delete(s.lfsActions, id)
		}
	}
}

func githubLFSHeaders(value any) http.Header {
	headers := http.Header{}
	values, ok := value.(map[string]any)
	if !ok {
		return headers
	}
	for key, raw := range values {
		value, ok := raw.(string)
		if ok && !httpx.HopByHopHeader(key) && !strings.EqualFold(key, "Cookie") && !strings.EqualFold(key, "Proxy-Authorization") {
			headers.Set(key, value)
		}
	}
	return headers
}

func githubLFSSize(value any) (string, bool) {
	var text string
	switch value := value.(type) {
	case json.Number:
		text = value.String()
	case string:
		text = value
	default:
		return "", false
	}
	parsed, err := strconv.ParseUint(text, 10, 63)
	return text, err == nil && parsed <= uint64(^uint64(0)>>1)
}

func validGitHubLFSOID(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF", char) {
			return false
		}
	}
	return true
}

func githubLFSMethodMatches(expected, actual string) bool {
	return expected == actual || expected == http.MethodGet && actual == http.MethodHead || expected == http.MethodPut && actual == http.MethodPatch
}

func randomGitHubLFSActionID() (string, error) {
	var value [24]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func requestScheme(request *http.Request) string {
	if request.TLS != nil {
		return "https"
	}
	return "http"
}

func sameOrigin(left, right *url.URL) bool {
	return left != nil && right != nil && strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}
