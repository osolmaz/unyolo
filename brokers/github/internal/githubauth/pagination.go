package githubauth

import (
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/osolmaz/unyolo/brokers/github/internal/opbinding"
)

// RESTPagination contains only forward-page facts, never upstream URLs, raw
// headers, or totals. A nil value means unavailable, NOT a terminal page.
// HasNext=false proves only that this successful forward response has no next
// link; it does not prove that earlier pages were read or form a stable snapshot.
type RESTPagination struct {
	HasNext   bool   `json:"has_next"`
	NextAfter string `json:"next_after,omitempty"`
}

var (
	// Deliberately accept a small Link subset. Extensions and ambiguous syntax
	// are unavailable rather than silently ignored (which could imply terminal).
	paginationLink   = regexp.MustCompile(`^<([^<>\s]+)>[ \t]*;[ \t]*rel=(?:"(next|prev)"|(next|prev))[ \t]*(?:,|$)`)
	paginationCursor = regexp.MustCompile(`^[A-Za-z0-9_+/\-]{1,256}={0,2}$`)
)

func restPagination(response *http.Response, binding opbinding.Binding) *RESTPagination {
	// Other Link bindings have different cursor contracts and remain unchanged.
	if !projectPaginationBinding(binding) || !paginationResponse(response) {
		return nil
	}
	origin := response.Request.URL
	if !paginationOrigin(origin) {
		return nil
	}
	requestQuery, ok := paginationQuery(origin.RawQuery)
	if !ok || requestQuery.Has("before") {
		return nil
	}
	seen, ok := paginationRelations(response.Header.Values("Link"), origin, requestQuery)
	if !ok {
		return nil
	}
	next, hasNext := seen["next"]
	if hasNext && (next == requestQuery.Get("after") || next == seen["prev"]) {
		return nil
	}
	return &RESTPagination{HasNext: hasNext, NextAfter: next}
}

func projectPaginationBinding(binding opbinding.Binding) bool {
	return binding.Operation == "project.projects_list_items_for_org" && binding.Pagination == "link" && binding.Method == http.MethodGet && binding.ResponseRootType == "array"
}

func paginationResponse(response *http.Response) bool {
	// A declared trailer cannot be mistaken for an absent Link header.
	_, hasTrailer := response.Trailer["Link"]
	return !hasTrailer && response.StatusCode == http.StatusOK && response.Request != nil && response.Request.URL != nil && response.Request.Method == http.MethodGet
}

func paginationRelations(lines []string, origin *url.URL, query url.Values) (map[string]string, bool) {
	size := 0
	seen := map[string]string{}
	for _, line := range lines {
		size += len(line)
		if size > 8192 || !paginationHeaderLine(line) {
			return nil, false
		}
		if !collectPaginationRelations(strings.TrimSpace(line), origin, query, seen) {
			return nil, false
		}
	}
	return seen, true
}

func paginationHeaderLine(line string) bool {
	if strings.TrimSpace(line) == "" {
		return false
	}
	for _, char := range line {
		if (char < 32 && char != '\t') || char > 126 {
			return false
		}
	}
	return true
}

func collectPaginationRelations(remaining string, origin *url.URL, query url.Values, seen map[string]string) bool {
	for remaining != "" {
		match := paginationLink.FindStringSubmatch(remaining)
		if match == nil {
			return false
		}
		relation := match[2]
		if relation == "" {
			relation = match[3]
		}
		if _, exists := seen[relation]; exists {
			return false
		}
		cursor, valid := paginationLinkCursor(origin, query, match[1], relation)
		if !valid {
			return false
		}
		seen[relation] = cursor
		consumed := match[0]
		remaining = strings.TrimSpace(remaining[len(consumed):])
		if strings.HasSuffix(consumed, ",") && remaining == "" {
			return false
		}
	}
	return true
}

func paginationOrigin(value *url.URL) bool {
	return (value.Scheme == "https" || value.Scheme == "http") && value.Host != "" && value.User == nil && value.Opaque == "" && value.Fragment == "" && value.RawFragment == "" && !value.ForceQuery
}

func paginationLinkCursor(origin *url.URL, requestQuery url.Values, raw, relation string) (string, bool) {
	if len(raw) > 2048 {
		return "", false
	}
	link, err := url.Parse(raw)
	if err != nil || !samePaginationOrigin(origin, link) {
		return "", false
	}
	query, ok := paginationQuery(link.RawQuery)
	if !ok || !samePaginationSelectors(requestQuery, query) {
		return "", false
	}
	cursorName, other := "after", "before"
	if relation == "prev" {
		cursorName, other = other, cursorName
	}
	cursor := query.Get(cursorName)
	return cursor, safePaginationCursor(cursor) && !query.Has(other)
}

func samePaginationOrigin(origin, link *url.URL) bool {
	return paginationOrigin(link) && link.Scheme == origin.Scheme && link.Host == origin.Host && link.EscapedPath() == origin.EscapedPath()
}

func samePaginationSelectors(request, link url.Values) bool {
	// Never let a provider URL change filters, selected fields, or page size.
	for _, key := range []string{"q", "fields", "per_page"} {
		if link.Has(key) != request.Has(key) || !slices.Equal(link[key], request[key]) {
			return false
		}
	}
	return true
}

func paginationQuery(raw string) (url.Values, bool) {
	if len(raw) > 4096 {
		return nil, false
	}
	query, err := url.ParseQuery(raw)
	if err != nil || (query.Has("after") && query.Has("before")) {
		return nil, false
	}
	for key, values := range query {
		if !paginationQueryValue(key, values) {
			return nil, false
		}
	}
	return query, true
}

func paginationQueryValue(key string, values []string) bool {
	if key == "fields" {
		return len(values) > 0 && len(values) <= 50
	}
	if len(values) != 1 {
		return false
	}
	switch key {
	case "q", "per_page":
		return true
	case "after", "before":
		return safePaginationCursor(values[0])
	default:
		return false
	}
}

func safePaginationCursor(cursor string) bool {
	if len(cursor) > 256 || !paginationCursor.MatchString(cursor) {
		return false
	}
	lower := strings.ToLower(cursor)
	for _, prefix := range []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "bearer", "token", "eyj"} {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	return true
}
