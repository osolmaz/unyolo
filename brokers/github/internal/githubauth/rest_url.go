package githubauth

import (
	"errors"
	"net/url"
	"strings"

	"github.com/osolmaz/brokerkit/brokers/github/internal/opbinding"
)

func (m *Manager) restURL(path string, query url.Values) (string, error) {
	unescapedPath, err := url.PathUnescape(path)
	if err != nil {
		return "", errors.New("GitHub API path is invalid")
	}
	return m.relativeAPIURL(m.apiURL, unescapedPath, path, query), nil
}

func (m *Manager) bindingRESTURL(binding opbinding.Binding, path string, query url.Values) (string, error) {
	unescapedPath, err := url.PathUnescape(path)
	if err != nil {
		return "", errors.New("GitHub API path is invalid")
	}
	return m.bindingURL(binding, unescapedPath, path, query)
}

func (m *Manager) bindingURL(binding opbinding.Binding, unescapedPath, escapedPath string, query url.Values) (string, error) {
	base := m.apiURL
	role := binding.ServerRole
	if role == "" {
		role = "api"
	}
	if role == "uploads" && strings.EqualFold(m.apiURL.Hostname(), "api.github.com") {
		base = &url.URL{Scheme: "https", Host: "uploads.github.com", Path: "/"}
	}
	if role != "api" && role != "uploads" {
		return "", errors.New("GitHub API server role is invalid")
	}
	return m.relativeAPIURL(base, unescapedPath, escapedPath, query), nil
}

func (m *Manager) relativeAPIURL(base *url.URL, unescapedPath, escapedPath string, query url.Values) string {
	relative := &url.URL{Path: strings.TrimPrefix(unescapedPath, "/"), RawPath: strings.TrimPrefix(escapedPath, "/"), RawQuery: query.Encode()}
	return base.ResolveReference(relative).String()
}
