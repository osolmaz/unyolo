// Package httpapi exposes the broker HTTP surface.
package httpapi

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/authorization/grants"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfgrant"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfplan"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/jsend"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/telemetry/audit"
)

func (s *Server) handleAPIRepos(w http.ResponseWriter, r *http.Request, client string) {
	query, reason, ok := readRepoListQuery(w, r)
	if !ok {
		s.record(client, string(policy.OpRepoList), "repos", audit.DecisionRefused, reason, 0)
		return
	}
	repos, err := s.listReposForClient(r.Context(), client, query)
	if err != nil {
		writeJSendError(w, http.StatusBadGateway, "Could not list Hugging Face repositories", "upstream_unavailable")
		s.record(client, string(policy.OpRepoList), "repos", audit.DecisionRefused, "upstream_unavailable", 0)
		return
	}
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

func (s *Server) listReposForClient(ctx context.Context, client string, query repoListQuery) ([]apiRepoBody, error) {
	repos := make([]apiRepoBody, 0)
	seen := map[string]bool{}
	for _, source := range repoListSources(s.policy, client, query) {
		upstream, err := s.hubClient.ListRepos(ctx, source.repoType, source.owner, 100)
		if err != nil {
			return nil, err
		}
		for _, candidate := range upstream {
			repo, ok := s.disclosedRepo(client, source.repoType, candidate, query)
			if !ok || seen[repoKey(repo)] {
				continue
			}
			seen[repoKey(repo)] = true
			repos = append(repos, repo)
			if len(repos) >= query.limit {
				return repos, nil
			}
		}
	}
	return repos, nil
}

type repoListSource struct {
	repoType hubclient.RepoType
	owner    string
}

func repoListSources(pol policy.Policy, client string, query repoListQuery) []repoListSource {
	seen := map[repoListSource]bool{}
	var result []repoListSource
	for _, rule := range pol.Rules() {
		if !ruleMayDiscloseRepoListTarget(rule, client) {
			continue
		}
		for _, target := range rule.Targets {
			for _, source := range repoListTargetSources(target, query) {
				if !seen[source] {
					seen[source] = true
					result = append(result, source)
				}
			}
		}
	}
	return result
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

func repoListTargetSources(target policy.TargetMatcher, query repoListQuery) []repoListSource {
	if !validRepoListSourceTarget(target, query) {
		return nil
	}
	types := repoListSourceTypes(target.Type, query.filterType)
	result := make([]repoListSource, 0, len(types))
	for _, repoType := range types {
		result = append(result, repoListSource{repoType: hubclient.RepoType(repoType), owner: target.Owner})
	}
	return result
}

func validRepoListSourceTarget(target policy.TargetMatcher, query repoListQuery) bool {
	return target.Kind == policy.KindRepo && target.Owner != "" && !strings.ContainsAny(target.Owner, "*?") &&
		(query.filterOwner == "" || query.filterOwner == target.Owner) &&
		(query.filterType == "" || target.Type == policy.TypeAny || target.Type == query.filterType)
}

func repoListSourceTypes(targetType, filterType policy.RepoType) []policy.RepoType {
	if filterType != "" {
		return []policy.RepoType{filterType}
	}
	if targetType != policy.TypeAny {
		return []policy.RepoType{targetType}
	}
	return []policy.RepoType{policy.TypeModel, policy.TypeDataset, policy.TypeSpace, policy.TypeKernel}
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

func (s *Server) disclosedRepo(client string, repoType hubclient.RepoType, candidate hubclient.RepoSummary, query repoListQuery) (apiRepoBody, bool) {
	parts := strings.Split(candidate.ID, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || (query.filterOwner != "" && query.filterOwner != parts[0]) {
		return apiRepoBody{}, false
	}
	target := policy.Target{Kind: policy.KindRepo, Type: policy.RepoType(repoType), Owner: parts[0], Name: parts[1]}
	if !policyAllowsListedRepo(client, s.policy, target, s.utcNow()) {
		return apiRepoBody{}, false
	}
	return apiRepoBody{Type: string(repoType), Owner: parts[0], Name: parts[1]}, true
}

func policyAllowsListedRepo(client string, pol policy.Policy, target policy.Target, now time.Time) bool {
	return policyAllowsRepoOperation(client, pol, target, policy.OpRepoList, now) &&
		policyAllowsRepoOperation(client, pol, target, policy.OpRepoMetadataRead, now)
}

func policyAllowsRepoOperation(client string, pol policy.Policy, target policy.Target, operation policy.Operation, now time.Time) bool {
	req := policy.Request{Client: client, Operation: operation, Target: target}
	return pol.Decide(req, nil, now, false).Effect == policy.EffectAllow
}

func policyAllowsRepositoryResult(client string, pol policy.Policy, target policy.Target, operation policy.Operation,
	authority *grants.Grant, validator hfplan.Validator, now time.Time) bool {
	request := policy.Request{Client: client, Operation: operation, Target: target}
	decision := pol.Decide(request, nil, now, false)
	if len(decision.MatchedDenyRuleIDs) > 0 {
		return false
	}
	if decision.Effect == policy.EffectAllow {
		return true
	}
	if authority == nil {
		return false
	}
	return reservedResultGrantAllows(*authority, request, pol, validator, now)
}

func reservedResultGrantAllows(grant grants.Grant, request policy.Request, pol policy.Policy,
	validator hfplan.Validator, now time.Time) bool {
	if !validReservedResultGrant(grant, request.Client, request.Operation, validator, now) {
		return false
	}
	authorized, err := hfgrant.PolicyTarget(grant)
	if err != nil {
		return false
	}
	authorized = resultGrantTarget(authorized, request.Operation)
	rule := policy.GeneratedGrantRule(grant.ID, grant.Client, request.Operation, authorized, grant.ExpiresAt, 1)
	decision := pol.Decide(request, []policy.Rule{rule}, now, false)
	return decision.GrantID == grant.ID
}

func resultGrantTarget(target policy.Target, operation policy.Operation) policy.Target {
	if operation == policy.OpRepoTreeList {
		target.Paths = recursiveResultScopes(target.Paths)
	}
	if operation == policy.OpBucketObjectList {
		target.Keys = recursiveResultScopes(target.Keys)
	}
	return target
}

func recursiveResultScopes(values []string) []string {
	result := make([]string, len(values))
	for index, value := range values {
		if strings.HasSuffix(value, "/**") {
			result[index] = value
		} else {
			result[index] = value + "/**"
		}
	}
	return result
}

func validReservedResultGrant(grant grants.Grant, client string, operation policy.Operation,
	validator hfplan.Validator, now time.Time) bool {
	return grant.Status == grants.StatusActive && !grant.ReservationRetained && grant.ReservedCount > 0 &&
		grant.Client == client && grant.Operation == string(operation) && runtimeWindowGrant(grant) &&
		now.Before(grant.ExpiresAt) && validator.ValidateExecution(grant) == nil
}

func repoKey(repo apiRepoBody) string {
	return repo.Type + "/" + repo.Owner + "/" + repo.Name
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
	target, _ := hfgrant.PolicyTarget(grant)
	return target
}

func targetNameFromPolicy(target policy.Target) string {
	if target.Kind == policy.KindRepo {
		return string(target.Type) + "/" + target.Owner + "/" + target.Name
	}
	return string(target.Kind) + "/" + target.Owner + "/" + target.Name
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
