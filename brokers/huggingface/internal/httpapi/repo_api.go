// Package httpapi exposes the broker HTTP surface.
package httpapi

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfgrant"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/jsend"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/grants"
)

func (s *Server) handleAPIRepos(w http.ResponseWriter, r *http.Request, client string) {
	query, reason, ok := readRepoListQuery(w, r)
	if !ok {
		s.record(client, string(policy.OpRepoList), "repos", audit.DecisionRefused, reason, 0)
		return
	}
	repos := s.listReposForClient(client, query)
	writeJSendSuccess(w, http.StatusOK, map[string]any{"repos": repos, "next_cursor": nil})
	s.record(client, string(policy.OpRepoList), "repos", audit.DecisionAllowed, "", 0)
}

func readRepoListQuery(w http.ResponseWriter, r *http.Request) (repoListQuery, string, bool) {
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		writeJSendFail(w, http.StatusBadRequest, "invalid_cursor", "Invalid cursor")
		return repoListQuery{}, "invalid_cursor", false
	}
	limit, ok := parseRepoListLimit(r.URL.Query().Get("limit"))
	if !ok {
		writeJSendFail(w, http.StatusBadRequest, "invalid_limit", "Invalid limit")
		return repoListQuery{}, "invalid_limit", false
	}
	return repoListQuery{
		limit:       limit,
		filterType:  policy.RepoType(r.URL.Query().Get("type")),
		filterOwner: r.URL.Query().Get("owner"),
	}, "", true
}

func (s *Server) listReposForClient(client string, query repoListQuery) []apiRepoBody {
	repos := make([]apiRepoBody, 0)
	seen := map[string]bool{}
	for _, rule := range s.policy.Rules() {
		repos = s.appendReposFromRule(client, rule, query, repos, seen)
		if len(repos) >= query.limit {
			return repos
		}
	}
	return repos
}

func (s *Server) appendReposFromRule(client string, rule policy.Rule, query repoListQuery, repos []apiRepoBody, seen map[string]bool) []apiRepoBody {
	if !ruleMayDiscloseRepoListTarget(rule, client) {
		return repos
	}
	for _, target := range rule.Targets {
		repos = s.appendListedRepo(client, target, query, repos, seen)
		if len(repos) >= query.limit {
			return repos
		}
	}
	return repos
}

func (s *Server) appendListedRepo(client string, target policy.TargetMatcher, query repoListQuery, repos []apiRepoBody, seen map[string]bool) []apiRepoBody {
	repo, ok := listedRepoForTarget(client, s.policy, target, query, s.utcNow())
	if !ok || seen[repoKey(repo)] {
		return repos
	}
	seen[repoKey(repo)] = true
	return append(repos, repo)
}

func ruleMayDiscloseRepoListTarget(rule policy.Rule, client string) bool {
	return rule.Effect == policy.EffectAllow &&
		stringListContains(rule.Clients, "*", client) &&
		(operationListContains(rule.Operations, policy.OpRepoList) ||
			operationListContains(rule.Operations, policy.OpRepoMetadataRead))
}

func stringListContains(values []string, wants ...string) bool {
	for _, value := range values {
		for _, want := range wants {
			if value == want {
				return true
			}
		}
	}
	return false
}

func operationListContains(values []policy.Operation, want policy.Operation) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func parseRepoListLimit(value string) (int, bool) {
	if value == "" {
		return 100, true
	}
	limit, err := strconv.Atoi(value)
	if err != nil || !repoListLimitInBounds(limit) {
		return 0, false
	}
	return limit, true
}

func repoListLimitInBounds(limit int) bool {
	return limit >= 1 && limit <= 100
}

func listedRepoForTarget(client string, pol policy.Policy, target policy.TargetMatcher, query repoListQuery, now time.Time) (apiRepoBody, bool) {
	if !targetIsListCandidate(target, query) {
		return apiRepoBody{}, false
	}
	reqTarget := repoTargetFromMatcher(target)
	if !policyAllowsListedRepo(client, pol, reqTarget, now) {
		return apiRepoBody{}, false
	}
	return apiRepoBody{Type: string(target.Type), Owner: target.Owner, Name: target.Name}, true
}

func targetIsListCandidate(target policy.TargetMatcher, query repoListQuery) bool {
	return target.Kind == policy.KindRepo &&
		exactRepoTarget(target) &&
		repoTargetMatchesListQuery(target, query)
}

func repoTargetMatchesListQuery(target policy.TargetMatcher, query repoListQuery) bool {
	if query.filterType != "" && target.Type != query.filterType {
		return false
	}
	return query.filterOwner == "" || target.Owner == query.filterOwner
}

func repoTargetFromMatcher(target policy.TargetMatcher) policy.Target {
	return policy.Target{Kind: policy.KindRepo, Type: target.Type, Owner: target.Owner, Name: target.Name}
}

func policyAllowsListedRepo(client string, pol policy.Policy, target policy.Target, now time.Time) bool {
	return policyAllowsRepoOperation(client, pol, target, policy.OpRepoList, now) &&
		policyAllowsRepoOperation(client, pol, target, policy.OpRepoMetadataRead, now)
}

func policyAllowsRepoOperation(client string, pol policy.Policy, target policy.Target, operation policy.Operation, now time.Time) bool {
	req := policy.Request{Client: client, Operation: operation, Target: target}
	return pol.Decide(req, nil, now, false).Effect == policy.EffectAllow
}

func repoKey(repo apiRepoBody) string {
	return repo.Type + "/" + repo.Owner + "/" + repo.Name
}

func exactRepoTarget(target policy.TargetMatcher) bool {
	return target.Type != policy.TypeAny &&
		target.Owner != "" &&
		target.Name != "" &&
		!strings.ContainsAny(string(target.Type), "*?") &&
		!strings.ContainsAny(target.Owner, "*?") &&
		!strings.ContainsAny(target.Name, "*?")
}

func validGrantStatusFilter(value string) bool {
	switch value {
	case string(grants.StatusPending), string(grants.StatusActive), string(grants.StatusExpired), string(grants.StatusConsumed), string(grants.StatusDenied), string(grants.StatusCanceled), retainedGrantStatus, "revoked":
		return true
	default:
		return false
	}
}

func grantStatusMatchesFilter(grant grants.Grant, filter string) bool {
	if matched, handled := retainedGrantMatchesFilter(grant, filter); handled {
		return matched
	}
	if filter == "revoked" {
		return grant.Status == grants.StatusCanceled
	}
	return filter == "" || string(grant.Status) == filter
}

func apiGrantFromStore(grant grants.Grant, target policy.Target) apiGrantBody {
	pendingUntil := timeStringPtr(grant.PendingExpiresAt)
	expiresAt := grantExpiresAtStringPtr(grant)
	attrs, _ := hfgrant.Attrs(grant)
	return apiGrantBody{
		ID:              grant.ID,
		Status:          apiGrantStatus(grant),
		Operation:       grant.Operation,
		Target:          target,
		Attrs:           attrsOrEmpty(attrs),
		Mode:            grantModeFromStore(grant),
		Minutes:         hfgrant.RequestedMinutes(grant),
		MaxUses:         grant.MaxUses,
		UsesRemaining:   grantUsesRemaining(grant),
		UsedCount:       grant.UsedCount,
		PendingUntil:    pendingUntil,
		ExpiresAt:       expiresAt,
		ClientRequestID: grant.ClientRequestID,
	}
}

func grantExpiresAtStringPtr(grant grants.Grant) *string {
	switch grant.Status {
	case grants.StatusActive, grants.StatusConsumed:
		return timeStringPtr(grant.ExpiresAt)
	case grants.StatusExpired:
		if grant.ExpiredFrom == grants.StatusActive {
			return timeStringPtr(grant.ExpiresAt)
		}
		return nil
	default:
		return nil
	}
}

func grantModeFromStore(grant grants.Grant) policy.GrantMode {
	switch hfgrant.Mode(grant) {
	case hfgrant.ModeExecution:
		return policy.GrantModeExecution
	default:
		return policy.GrantModeWindow
	}
}

func attrsOrEmpty(attrs map[string]any) map[string]any {
	switch attrs {
	case nil:
		return make(map[string]any)
	default:
		return attrs
	}
}

func grantUsesRemaining(grant grants.Grant) int {
	if !grantIsActive(grant) || grantIsRetained(grant) {
		return 0
	}
	remaining, finite := grant.MaxUses.Remaining(grant.UsedCount, grant.ReservedCount)
	if !finite {
		return 0
	}
	return remaining
}

func hasGrantUses(grant grants.Grant) bool {
	return grant.MaxUses.Allows(grant.UsedCount, grant.ReservedCount)
}

func grantIsActive(grant grants.Grant) bool {
	return grant.Status == grants.StatusActive
}

func timeStringPtr(value time.Time) *string {
	if value.IsZero() {
		return nil
	}
	formatted := value.Format(time.RFC3339)
	return &formatted
}

func targetFromGrant(grant grants.Grant) policy.Target {
	rt, ok := parseGrantTarget(hfgrant.Target(grant))
	if !ok {
		return policy.Target{}
	}
	target := routeTarget(rt, nil)
	if ref := hfgrant.Ref(grant); ref != "" {
		target.Refs = []string{ref}
	}
	return target
}

func targetNameFromPolicy(target policy.Target) string {
	if target.Kind != policy.KindRepo {
		return ""
	}
	return string(target.Type) + "/" + target.Owner + "/" + target.Name
}

func writeJSendSuccess(w http.ResponseWriter, status int, data any) {
	writeJSON(w, status, jsend.Success(data))
}

func writeJSendFail(w http.ResponseWriter, status int, reason, message string) {
	writeJSON(w, status, jsend.Fail(map[string]any{"reason": reason, "message": message}))
}

func writeJSendError(w http.ResponseWriter, status int, message, code string) {
	writeJSON(w, status, jsend.Error(message, code))
}
