package httpx

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestReadLimited(t *testing.T) {
	t.Parallel()
	body, err := ReadLimited(strings.NewReader("abc"), 3)
	if err != nil || string(body) != "abc" {
		t.Fatalf("ReadLimited(exact) = %q, %v; want abc, nil", string(body), err)
	}
	empty, err := ReadLimited(strings.NewReader(""), 0)
	if err != nil || string(empty) != "" {
		t.Fatalf("ReadLimited(empty) = %q, %v; want empty, nil", string(empty), err)
	}
	if _, err := ReadLimited(strings.NewReader("abcd"), 3); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("ReadLimited(too large) error = %v, want ErrBodyTooLarge", err)
	}
	if _, err := ReadLimited(strings.NewReader("abc"), -1); err == nil || !strings.Contains(err.Error(), "non-negative") {
		t.Fatalf("ReadLimited(negative) error = %v, want non-negative limit error", err)
	}
}

func TestCopyHeaders(t *testing.T) {
	t.Parallel()
	src := http.Header{}
	src.Add("X-Keep", "one")
	src.Add("X-Keep", "two")
	src.Set("Authorization", "secret")
	src.Set("Connection", "close")
	dst := http.Header{}

	CopyHeaders(dst, src, DropAny(HopByHopHeader, RequestCredentialHeader))

	if got := strings.Join(dst.Values("X-Keep"), ","); got != "one,two" {
		t.Fatalf("copied X-Keep = %q, want both values", got)
	}
	for _, key := range []string{"Authorization", "Connection"} {
		if got := dst.Values(key); len(got) != 0 {
			t.Fatalf("%s copied as %v, want dropped", key, got)
		}
	}

	CopyHeaders(nil, src, nil)
}

func TestCopyHeadersDropsConnectionNominatedRequestHeaders(t *testing.T) {
	t.Parallel()
	src := http.Header{}
	src.Add("Connection", "X-Hop, X-Also-Hop")
	src.Set("X-Hop", "one")
	src.Set("X-Also-Hop", "two")
	src.Set("X-Keep", "safe")
	dst := http.Header{}

	CopyHeaders(dst, src, ProxyRequestHeader)

	for _, key := range []string{"Connection", "X-Hop", "X-Also-Hop"} {
		if got := dst.Values(key); len(got) != 0 {
			t.Fatalf("%s copied as %v, want dropped", key, got)
		}
	}
	if got := dst.Get("X-Keep"); got != "safe" {
		t.Fatalf("X-Keep = %q, want safe", got)
	}
}

func TestCopyHeadersDropsConnectionNominatedResponseHeaders(t *testing.T) {
	t.Parallel()
	src := http.Header{}
	src.Add("connection", "X-Hop")
	src.Add("Connection", " X-Second-Hop , ")
	src.Set("x-hop", "one")
	src.Set("X-Second-Hop", "two")
	src.Set("X-RateLimit-Remaining", "1")
	dst := http.Header{}

	CopyHeaders(dst, src, ProxyResponseHeader)

	for _, key := range []string{"Connection", "X-Hop", "X-Second-Hop"} {
		if got := dst.Values(key); len(got) != 0 {
			t.Fatalf("%s copied as %v, want dropped", key, got)
		}
	}
	if got := dst.Get("X-RateLimit-Remaining"); got != "1" {
		t.Fatalf("X-RateLimit-Remaining = %q, want 1", got)
	}
}

func TestCopyHeadersKeepsConnectionNominatedHeadersWhenConnectionIsCopied(t *testing.T) {
	t.Parallel()
	src := http.Header{}
	src.Set("Connection", "X-Forwarded")
	src.Set("X-Forwarded", "kept")
	dst := http.Header{}

	CopyHeaders(dst, src, nil)

	if got := dst.Get("Connection"); got != "X-Forwarded" {
		t.Fatalf("Connection = %q, want X-Forwarded", got)
	}
	if got := dst.Get("X-Forwarded"); got != "kept" {
		t.Fatalf("X-Forwarded = %q, want kept", got)
	}
}

func TestHeaderDroppers(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		drop HeaderDropper
		key  string
		want bool
	}{
		"hop by hop":              {drop: HopByHopHeader, key: "Connection", want: true},
		"proxy connection":        {drop: HopByHopHeader, key: "Proxy-Connection", want: true},
		"request credential":      {drop: RequestCredentialHeader, key: "cookie", want: true},
		"response credential":     {drop: ResponseCredentialHeader, key: "Set-Cookie", want: true},
		"proxy request":           {drop: ProxyRequestHeader, key: "Authorization", want: true},
		"proxy response":          {drop: ProxyResponseHeader, key: "WWW-Authenticate", want: true},
		"rewritten body":          {drop: RewrittenBodyHeader, key: "Content-Length", want: true},
		"safe forwarded response": {drop: ProxyResponseHeader, key: "X-RateLimit-Remaining", want: false},
		"safe rewritten body":     {drop: RewrittenBodyHeader, key: "Content-Type", want: false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := tc.drop(tc.key); got != tc.want {
				t.Fatalf("%s(%q) = %v, want %v", name, tc.key, got, tc.want)
			}
		})
	}
	if drop := DropAny(nil, func(string) bool { return false }); drop("Authorization") {
		t.Fatal("DropAny(false-only) = true, want false")
	}
}

func TestNoStore(t *testing.T) {
	t.Parallel()
	header := http.Header{}
	NoStore(header)
	if header.Get("Cache-Control") != "no-store" ||
		header.Get("Pragma") != "no-cache" ||
		header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("NoStore() headers = %+v", header)
	}
}
