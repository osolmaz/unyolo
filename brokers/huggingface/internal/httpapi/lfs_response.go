// Package httpapi exposes the broker HTTP surface.
package httpapi

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"time"
)

func (s *Server) rewriteLFSBatchActions(r *http.Request, rt route, payload map[string]any) {
	objects, ok := payload["objects"].([]any)
	if !ok {
		return
	}
	for _, rawObject := range objects {
		object, ok := rawObject.(map[string]any)
		if !ok {
			continue
		}
		s.rewriteLFSObjectActions(r, rt, object)
	}
}

func (s *Server) rewriteLFSObjectActions(r *http.Request, rt route, object map[string]any) {
	oid, _ := object["oid"].(string)
	size, _ := lfsObjectSizeString(object["size"])
	actions, ok := object["actions"].(map[string]any)
	if !ok {
		return
	}
	for name, rawAction := range actions {
		action, ok := rawAction.(map[string]any)
		if !ok {
			delete(actions, name)
			continue
		}
		actionID, ok := s.registerLFSAction(rt, oid, size, name, action)
		if !ok {
			delete(actions, name)
			continue
		}
		href, ok := brokerLFSActionHref(r, rt, oid, size, name, actionID)
		if !ok {
			delete(actions, name)
			continue
		}
		action["href"] = href
		delete(action, "header")
	}
}

func (s *Server) registerLFSAction(rt route, oid, size, name string, action map[string]any) (string, bool) {
	href, ok := action["href"].(string)
	if !ok {
		return "", false
	}
	parsed, err := url.Parse(href)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", false
	}
	actionRoute, ok := brokerLFSActionRoute(rt, oid, size, name)
	if !ok {
		return "", false
	}
	id, err := s.nextLFSActionID()
	if err != nil {
		return "", false
	}
	s.lfsMu.Lock()
	defer s.lfsMu.Unlock()
	now := s.utcNow()
	s.pruneExpiredLFSActions(now)
	s.lfsActions[id] = lfsAction{url: href, headers: parseLFSActionHeaders(action["header"]), route: actionRoute, created: now}
	return id, true
}

func (s *Server) lookupLFSAction(id string) (lfsAction, bool) {
	s.lfsMu.Lock()
	defer s.lfsMu.Unlock()
	action, ok := s.lfsActions[id]
	if !ok || s.utcNow().Sub(action.created) > lfsActionTTL {
		delete(s.lfsActions, id)
		return lfsAction{}, false
	}
	return action, true
}

func (s *Server) pruneExpiredLFSActions(now time.Time) {
	for id, action := range s.lfsActions {
		if now.Sub(action.created) > lfsActionTTL {
			delete(s.lfsActions, id)
		}
	}
}

func randomLFSActionID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func parseLFSActionHeaders(value any) http.Header {
	headers := http.Header{}
	rawHeaders, ok := value.(map[string]any)
	if !ok {
		return headers
	}
	for key, rawValue := range rawHeaders {
		if value, ok := rawValue.(string); ok {
			headers.Set(key, value)
		}
	}
	return headers
}

func lfsObjectSizeString(value any) (string, bool) {
	switch v := value.(type) {
	case json.Number:
		return v.String(), isDecimal(v.String())
	case string:
		return v, isDecimal(v)
	default:
		return "", false
	}
}

func brokerLFSActionHref(r *http.Request, rt route, oid, size, action, actionID string) (string, bool) {
	actionRoute, ok := brokerLFSActionRoute(rt, oid, size, action)
	if !ok {
		return "", false
	}
	u := url.URL{Scheme: brokerRequestScheme(r), Host: brokerRequestHost(r), Path: joinURLPath("", upstreamRepoPath(actionRoute)+"/"+actionRoute.tail)}
	q := u.Query()
	q.Set(lfsActionQuery, actionID)
	u.RawQuery = q.Encode()
	return u.String(), true
}

func brokerLFSActionRoute(rt route, oid, size, action string) (route, bool) {
	if !isLFSOID(oid) {
		return route{}, false
	}
	tail, ok := lfsActionTail(oid, size, action)
	if !ok {
		return route{}, false
	}
	return route{repoType: rt.repoType, owner: rt.owner, name: rt.name, tail: tail}, true
}

func lfsActionTail(oid, size, action string) (string, bool) {
	tail := "info/lfs/objects/" + oid
	switch action {
	case "download":
		return tail, true
	case "upload":
		return tail + "/" + size, isDecimal(size)
	case "verify":
		return tail + "/verify", true
	default:
		return "", false
	}
}

func sameRoute(a, b route) bool {
	return a.repoType == b.repoType && a.owner == b.owner && a.name == b.name && a.tail == b.tail
}

func brokerRequestScheme(r *http.Request) string {
	forwardedProto := r.Header.Get("X-Forwarded-Proto")
	if forwardedProto == "http" || forwardedProto == "https" {
		return forwardedProto
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func brokerRequestHost(r *http.Request) string {
	if r.Host != "" {
		return r.Host
	}
	return r.URL.Host
}
