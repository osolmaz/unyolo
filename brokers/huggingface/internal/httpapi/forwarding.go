// Package httpapi exposes the broker HTTP surface.
package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/gitproxy"
	"github.com/osolmaz/brokerkit/httpx"
)

func readLimited(r io.Reader, limit int64) ([]byte, bool, error) {
	var buf bytes.Buffer
	_, err := io.CopyN(&buf, r, limit+1)
	if err == nil {
		return buf.Bytes()[:limit], true, nil
	}
	if errors.Is(err, io.EOF) {
		return buf.Bytes(), false, nil
	}
	return nil, false, err
}

func (s *Server) forward(w http.ResponseWriter, r *http.Request, client string, rt route, body []byte, bodyRead bool) (int, error) {
	if actionID := r.URL.Query().Get(lfsActionQuery); actionID != "" {
		action, ok := s.lookupLFSAction(actionID)
		if !ok || action.client != client || !sameRoute(action.route, rt) {
			writePlain(w, http.StatusForbidden, "hf-broker: "+errInvalidLFSAction.Error()+"\n")
			return 0, errInvalidLFSAction
		}
		return s.forwardToURL(w, r, client, rt, action.url, body, bodyRead, action.headers, s.lfsActionNeedsHFToken(action.url, rt))
	}
	upstreamURL := s.upstreamRequestURL(r, rt)
	return s.forwardToURL(w, r, client, rt, upstreamURL, body, bodyRead, nil, true)
}

func (s *Server) lfsActionNeedsHFToken(rawURL string, rt route) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	repoPath := joinURLPath(s.upstream.Path, upstreamRepoPath(rt))
	return parsed.Scheme == s.upstream.Scheme &&
		parsed.Host == s.upstream.Host &&
		(parsed.Path == repoPath || strings.HasPrefix(parsed.Path, repoPath+"/"))
}

func (s *Server) forwardToURL(w http.ResponseWriter, r *http.Request, client string, rt route, upstreamURL string, body []byte, bodyRead bool, extraHeaders http.Header, injectHFToken bool) (int, error) {
	req, err := s.newForwardRequest(r, upstreamURL, body, bodyRead, extraHeaders, injectHFToken)
	if err != nil {
		return 0, err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	return s.writeForwardResponse(w, r, client, rt, resp)
}

func (s *Server) forwardReceivePack(w http.ResponseWriter, r *http.Request, rt route, push gitproxy.ReceivePackRequest, body []byte) (int, bool, string, bool, error) {
	req, err := s.newForwardRequest(r, s.upstreamRequestURL(r, rt), body, true, nil, true)
	if err != nil {
		return 0, false, "", false, err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return 0, false, "", false, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	responseBody, err := readReceivePackReport(resp.Body)
	if err != nil {
		return 0, false, "", false, err
	}
	accepted, reason, definitiveReject := receivePackAccepted(push, resp.StatusCode, responseBody)
	_ = writeBufferedResponse(w, resp, responseBody)
	return resp.StatusCode, accepted, reason, definitiveReject, nil
}

func readReceivePackReport(body io.Reader) ([]byte, error) {
	return httpx.ReadLimited(body, maxReceivePackReportBytes)
}

func receivePackAccepted(push gitproxy.ReceivePackRequest, statusCode int, body []byte) (bool, string, bool) {
	if statusCode < 200 || statusCode >= 300 {
		return false, fmt.Sprintf("upstream returned HTTP %d", statusCode), httpReceivePackRejectionDefinitive(statusCode)
	}
	accepted, reason, err := gitproxy.ReceivePackAccepted(push, body)
	if err != nil {
		return false, "could not parse upstream receive-pack report", false
	}
	return accepted, reason, false
}

func httpReceivePackRejectionDefinitive(statusCode int) bool {
	switch statusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType:
		return true
	default:
		return false
	}
}

func writeBufferedResponse(w http.ResponseWriter, resp *http.Response, body []byte) error {
	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, err := w.Write(body)
	return err
}

func (s *Server) newForwardRequest(r *http.Request, upstreamURL string, body []byte, bodyRead bool, extraHeaders http.Header, injectHFToken bool) (*http.Request, error) {
	var reader io.Reader
	if bodyRead {
		reader = bytes.NewReader(body)
	} else if r.Body != nil {
		reader = r.Body
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, reader)
	if err != nil {
		return nil, err
	}
	copyForwardHeaders(req.Header, r.Header)
	copyHeaders(req.Header, extraHeaders, func(string) bool { return false })
	if injectHFToken {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("x-access-token:"+s.hfToken)))
	}
	setForwardContentLength(req, r, body, bodyRead)
	return req, nil
}

func setForwardContentLength(req, original *http.Request, body []byte, bodyRead bool) {
	if bodyRead {
		req.ContentLength = int64(len(body))
		return
	}
	if original.ContentLength >= 0 {
		req.ContentLength = original.ContentLength
	}
}

func (s *Server) writeForwardResponse(w http.ResponseWriter, r *http.Request, client string, rt route, resp *http.Response) (int, error) {
	copyResponseHeaders(w.Header(), resp.Header)
	if shouldRewriteLFSBatchResponse(r, rt, resp.StatusCode) {
		body, err := s.rewriteLFSBatchResponse(r, client, rt, resp.Body)
		if err != nil {
			return resp.StatusCode, err
		}
		w.Header().Del("Content-Length")
		w.WriteHeader(resp.StatusCode)
		_, writeErr := w.Write(body)
		return resp.StatusCode, writeErr
	}
	w.WriteHeader(resp.StatusCode)
	_, copyErr := io.Copy(w, resp.Body)
	return resp.StatusCode, copyErr
}

func shouldRewriteLFSBatchResponse(r *http.Request, rt route, statusCode int) bool {
	return statusCode >= 200 && statusCode < 300 && r.Method == http.MethodPost && rt.tail == "info/lfs/objects/batch"
}

func (s *Server) rewriteLFSBatchResponse(r *http.Request, client string, rt route, body io.Reader) ([]byte, error) {
	var payload map[string]any
	if err := httpx.DecodeJSON(body, maxLFSBatchBytes, &payload, false); err != nil {
		return nil, fmt.Errorf("could not sanitize LFS batch response: %w", err)
	}
	s.rewriteLFSBatchActions(r, client, rt, payload)
	return json.Marshal(payload)
}
