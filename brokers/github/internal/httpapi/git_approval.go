package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/brokerkit/authorization/budget"
	"github.com/osolmaz/brokerkit/authorization/grants"
	corepolicy "github.com/osolmaz/brokerkit/authorization/policy"
	"github.com/osolmaz/brokerkit/brokers/github/internal/policy"
	"github.com/osolmaz/brokerkit/git/protocol"
	"github.com/osolmaz/brokerkit/operation/digest"
)

type receivePackApproval struct {
	GrantID string
	Status  grants.Status
}

var errGitApprovalChannelUnavailable = errors.New("approval channel is not configured")

func (s *Server) evaluateGitMutation(request policy.Request) (policy.Decision, policy.Decision, error) {
	decision, err := s.evaluateBrokerRequest(request)
	if err != nil {
		return policy.Decision{}, policy.Decision{}, err
	}
	if decision.Allowed {
		return decision, policy.Decision{}, nil
	}
	return decision, s.policy.EvaluateGrantRequest(request), nil
}

func (s *Server) authorizeReceivePackTransaction(
	c echo.Context,
	body []byte,
	commands []receivePackCommand,
	authorized []authorizedReceivePackRequest,
	requestable []requestableReceivePackRequest,
) ([]authorizedReceivePackRequest, *receivePackApproval, error) {
	request, decision, err := s.prepareReceivePackTransaction(c, body, commands, authorized, requestable)
	if err != nil {
		return nil, nil, err
	}
	result, err := s.requestReceivePackGrant(request)
	if err != nil {
		return nil, nil, echo.NewHTTPError(http.StatusInternalServerError, "could not create Git push approval")
	}
	plan := grantCreatePlan{request: requestable[0].Request, decision: decision}
	if _, _, err := s.notifyPendingGrant(c, plan, result.Grant.ID); err != nil {
		return nil, nil, err
	}
	for _, item := range requestable {
		s.audit(c, item.Request, "requires_grant", "operator approval requested", 0, item.Decision.MatchedRuleIDs)
	}
	approved, err := s.grants.WaitForDecision(c.Request().Context(), result.Grant.ID)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, nil, err
		}
		return nil, nil, echo.NewHTTPError(http.StatusInternalServerError, "could not wait for Git push approval")
	}
	if approved.Status != grants.StatusActive {
		return nil, &receivePackApproval{GrantID: approved.ID, Status: approved.Status}, nil
	}
	if err := s.revalidateReceivePackPolicy(requestable); err != nil {
		return nil, nil, err
	}
	for index := range authorized {
		if authorized[index].Decision.Allowed {
			continue
		}
		authorized[index].Decision = policy.Decision{
			Effect: policy.EffectAllow, Allowed: true, Reason: "grant_allowed",
			GrantID: approved.ID, MatchedRuleIDs: []string{approved.ID},
		}
	}
	return authorized, nil, nil
}

func (s *Server) requestReceivePackGrant(request grants.Request) (grants.RequestResult, error) {
	for attempt := 0; attempt < 3; attempt++ {
		result, _, err := s.requestGrant(request)
		if !errors.Is(err, grants.ErrIdempotencyConflict) {
			return result, err
		}
	}
	return grants.RequestResult{}, grants.ErrIdempotencyConflict
}

func (s *Server) revalidateReceivePackPolicy(items []requestableReceivePackRequest) error {
	for _, item := range items {
		decision := s.policy.EvaluateGrantRequest(item.Request)
		if decision.Effect != policy.EffectRequest || decision.GrantPolicy == nil {
			return echo.NewHTTPError(statusForDecision(decision), decision.Reason)
		}
	}
	return nil
}

func (s *Server) prepareReceivePackTransaction(
	c echo.Context,
	body []byte,
	commands []receivePackCommand,
	authorized []authorizedReceivePackRequest,
	items []requestableReceivePackRequest,
) (grants.Request, policy.Decision, error) {
	if s.notifier == nil && !s.operatorConfigured {
		return grants.Request{}, policy.Decision{}, echo.NewHTTPError(http.StatusServiceUnavailable, errGitApprovalChannelUnavailable.Error())
	}
	duration, pendingTimeout, err := receivePackApprovalBounds(items)
	if err != nil {
		return grants.Request{}, policy.Decision{}, echo.NewHTTPError(http.StatusForbidden, err.Error())
	}
	attrs := receivePackTransactionAttrs(body, commands, authorized)
	ruleIDs := receivePackRequestRuleIDs(items)
	requestID, err := s.gitTransactionRequestID(items[0].Request.Client, attrs, ruleIDs)
	if err != nil {
		return grants.Request{}, policy.Decision{}, err
	}
	request := grants.Request{
		Client: items[0].Request.Client, ClientRequestID: requestID,
		Operation: string(highestRiskGitOperation(items)), Target: policy.CoreTarget(items[0].Request.Target), Attrs: attrs,
		Reason: "Git push transaction requires approval", Duration: duration, PendingTimeout: pendingTimeout,
		MaxUses: usebudget.Limit(1), MaxUsesSpecified: true,
	}
	return request, policy.Decision{Effect: policy.EffectRequest, MatchedRuleIDs: ruleIDs}, nil
}

func receivePackApprovalBounds(items []requestableReceivePackRequest) (time.Duration, time.Duration, error) {
	var duration, pending time.Duration
	for _, item := range items {
		bounds := item.Decision.GrantPolicy
		if bounds == nil || corepolicy.GrantMode(bounds.Mode) != corepolicy.GrantModeWindow || bounds.MaxUses < 1 {
			return 0, 0, errors.New("Git push approval policy is incompatible with one-use transactions")
		}
		candidateDuration := time.Duration(bounds.DefaultMinutes) * time.Minute
		candidatePending := time.Duration(bounds.RequestTTLMinutes) * time.Minute
		if duration == 0 || candidateDuration < duration {
			duration = candidateDuration
		}
		if pending == 0 || candidatePending < pending {
			pending = candidatePending
		}
	}
	return duration, pending, nil
}

func receivePackTransactionAttrs(body []byte, commands []receivePackCommand, authorized []authorizedReceivePackRequest) map[string][]string {
	attrs := map[string][]string{
		"plan_digest": {plandigest.Digest(body)},
		"ref":         make([]string, 0, len(commands)),
		"old_oid":     make([]string, 0, len(commands)),
		"new_oid":     make([]string, 0, len(commands)),
		"command":     make([]string, 0, len(commands)),
	}
	for index, command := range commands {
		attrs["ref"] = append(attrs["ref"], command.Ref)
		attrs["old_oid"] = append(attrs["old_oid"], command.OldOID)
		attrs["new_oid"] = append(attrs["new_oid"], command.NewOID)
		attrs["command"] = append(attrs["command"], strings.Join([]string{
			fmt.Sprintf("%06d", index), string(authorized[index].Request.Operation), command.OldOID, command.NewOID, command.Ref,
		}, " "))
	}
	for _, item := range authorized {
		attrs["operation"] = append(attrs["operation"], string(item.Request.Operation))
	}
	for key := range attrs {
		slices.Sort(attrs[key])
	}
	return attrs
}

func receivePackRequestRuleIDs(items []requestableReceivePackRequest) []string {
	var ids []string
	for _, item := range items {
		ids = append(ids, item.Decision.MatchedRuleIDs...)
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

func highestRiskGitOperation(items []requestableReceivePackRequest) policy.Operation {
	rank := map[policy.Operation]int{
		policy.OperationGitPushBranchCreate: 1, policy.OperationGitPushFastForward: 2,
		policy.OperationGitTagUpdate: 3, policy.OperationGitPushForce: 4, policy.OperationGitRefDelete: 5,
	}
	selected := items[0].Request.Operation
	for _, item := range items[1:] {
		if rank[item.Request.Operation] > rank[selected] {
			selected = item.Request.Operation
		}
	}
	return selected
}

func (s *Server) gitTransactionRequestID(client string, attrs map[string][]string, ruleIDs []string) (string, error) {
	encoded, err := json.Marshal(struct {
		Attrs map[string][]string `json:"attrs"`
		Rules []string            `json:"rules"`
	}{Attrs: attrs, Rules: ruleIDs})
	if err != nil {
		return "", err
	}
	base := "git-transaction-" + plandigest.Digest(encoded)[:48]
	items, err := s.grants.ListForClient(client)
	if err != nil {
		return "", err
	}
	return nextGitApprovalRequestID(base, items), nil
}

func nextGitApprovalRequestID(base string, items []grants.Grant) string {
	latest, latestGeneration := latestGitApprovalGrant(base, items)
	if latestGeneration == 0 {
		return base
	}
	if latest.Status == grants.StatusPending || latest.Status == grants.StatusActive {
		return latest.ClientRequestID
	}
	return base + "-" + strconv.Itoa(latestGeneration+1)
}

func latestGitApprovalGrant(base string, items []grants.Grant) (grants.Grant, int) {
	var latest grants.Grant
	latestGeneration := 0
	for _, grant := range items {
		generation, ok := gitApprovalRequestGeneration(base, grant.ClientRequestID)
		if !ok || generation < latestGeneration || (generation == latestGeneration && !grant.CreatedAt.After(latest.CreatedAt)) {
			continue
		}
		latest, latestGeneration = grant, generation
	}
	return latest, latestGeneration
}

func gitApprovalRequestGeneration(base string, requestID string) (int, bool) {
	if requestID == base {
		return 1, true
	}
	if !strings.HasPrefix(requestID, base+"-") {
		return 0, false
	}
	generation, err := strconv.Atoi(strings.TrimPrefix(requestID, base+"-"))
	return generation, err == nil && generation >= 2
}

func writeReceivePackApprovalRequired(c echo.Context, request gitx.ReceivePackRequest, approval receivePackApproval) error {
	reason := "approval " + string(approval.Status) + " (" + approval.GrantID + ")"
	failures := make([]gitx.ReceivePackFailure, 0, len(request.Commands))
	for _, command := range request.Commands {
		failures = append(failures, gitx.ReceivePackFailure{Ref: command.Ref, Reason: reason})
	}
	report, err := gitx.BuildReceivePackRefusal("gh-broker", request, failures)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "could not render git approval response")
	}
	return c.Blob(http.StatusOK, "application/x-git-receive-pack-result", report)
}
