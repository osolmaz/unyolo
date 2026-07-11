package httpapi

import (
	"encoding/base64"
	"strings"

	"github.com/osolmaz/brokerkit/httpx"
)

var githubProxyResponseHeader = httpx.DropAny(
	httpx.HopByHopHeader,
	httpx.ResponseCredentialHeader,
	githubCredentialMetadataHeader,
)

var githubFilteredResponseHeader = httpx.DropAny(githubProxyResponseHeader, httpx.RewrittenBodyHeader)

func githubCredentialMetadataHeader(key string) bool {
	switch strings.ToLower(key) {
	case "authentication-info",
		"github-authentication-token-expiration",
		"www-authenticate",
		"x-accepted-oauth-scopes",
		"x-github-authentication-token-expiration",
		"x-github-sso",
		"x-oauth-scopes":
		return true
	default:
		return false
	}
}

func githubGitAuthorization(token string) string {
	credential := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	return "Basic " + credential
}
