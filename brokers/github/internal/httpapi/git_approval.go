package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	bkauthorization "github.com/osolmaz/brokerkit/authorization"
	"github.com/osolmaz/brokerkit/authorization/grants"
	corepolicy "github.com/osolmaz/brokerkit/authorization/policy"
	"github.com/osolmaz/brokerkit/brokers/github/internal/policy"
	"github.com/osolmaz/brokerkit/git/protocol"
	"github.com/osolmaz/brokerkit/operation/digest"
)

type receivePackApproval struct {
	Ref     string
	GrantID string
}

var errGitApprovalChannelUnavailable = errors.New("approval channel is not configured")

func (s *Server) authorizeGitMutation(c echo.Context, request policy.Request) (policy.Decision, *receivePackApproval, error) {
	core := policy.AuthorizationRequest(
		request.Client,
		string(request.Operation),
		request.Target.Kind,
		policy.CoreTarget(request.Target).Fields,
		corepolicy.SingletonValues(request.Attrs),
	)
	var result bkauthorization.Result
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		result, err = s.authorization.Authorize(core, func(decision corepolicy.Decision) (bkauthorization.GrantIntent, error) {
			return s.prepareGitApprovalIntent(request, core, decision)
		})
		if !errors.Is(err, grants.ErrIdempotencyConflict) {
			break
		}
	}
	decision := s.policy.AuthorizationDecision(result.Decision)
	if err != nil {
		if errors.Is(err, bkauthorization.ErrDenied) || errors.Is(err, bkauthorization.ErrNoMatch) {
			return decision, nil, nil
		}
		if errors.Is(err, errGitApprovalChannelUnavailable) {
			return decision, nil, echo.NewHTTPError(http.StatusServiceUnavailable, errGitApprovalChannelUnavailable.Error())
		}
		s.logger.Error("authorize Git push", "operation", request.Operation, "target", request.Target.Owner+"/"+request.Target.Name, "error", err)
		s.audit(c, request, "error", "could not authorize git push", 0, decision.MatchedRuleIDs)
		return policy.Decision{}, nil, echo.NewHTTPError(http.StatusInternalServerError, "could not authorize git push")
	}
	if result.Request.Grant.ID == "" {
		return decision, nil, nil
	}
	plan := grantCreatePlan{request: request, decision: decision}
	if _, _, err := s.notifyPendingGrant(c, plan, result.Request.Grant.ID); err != nil {
		return policy.Decision{}, nil, err
	}
	s.audit(c, request, "requires_grant", "operator approval requested", 0, decision.MatchedRuleIDs)
	return decision, &receivePackApproval{Ref: request.Attrs["ref"], GrantID: result.Request.Grant.ID}, nil
}

func (s *Server) prepareGitApprovalIntent(request policy.Request, authorization corepolicy.Request, decision corepolicy.Decision) (bkauthorization.GrantIntent, error) {
	bounds, err := s.gitApprovalBounds(decision)
	if err != nil {
		return bkauthorization.GrantIntent{}, err
	}
	id, err := s.gitApprovalRequestID(request.Client, authorization, decision.MatchedRequestRuleIDs)
	if err != nil {
		return bkauthorization.GrantIntent{}, err
	}
	grantRequest := grants.Request{
		Client: request.Client, ClientRequestID: id, Operation: string(request.Operation),
		Target: authorization.Target, Attrs: authorization.Attrs,
		Reason:   string(request.Operation) + " requires approval",
		Duration: time.Duration(bounds.DefaultMinutes) * time.Minute, PendingTimeout: time.Duration(bounds.RequestTTLMinutes) * time.Minute,
		MaxUses: bounds.DefaultMaxUses, MaxUsesDefaulted: true,
	}
	prepared, err := s.prepareGitGrantPlan(&grantRequest)
	if err != nil {
		return bkauthorization.GrantIntent{}, err
	}
	return bkauthorization.GrantIntent{
		Mode: corepolicy.GrantModeWindow, Authorization: authorization, Request: grantRequest, Plan: prepared,
	}, nil
}

func (s *Server) gitApprovalBounds(decision corepolicy.Decision) (*corepolicy.GrantPolicy, error) {
	if s.notifier == nil && !s.operatorConfigured {
		return nil, errGitApprovalChannelUnavailable
	}
	if decision.GrantPolicy == nil || corepolicy.GrantMode(decision.GrantPolicy.Mode) != corepolicy.GrantModeWindow {
		return nil, errors.New("Git push requires a window approval") //nolint:staticcheck // Git is a product name.
	}
	return decision.GrantPolicy, nil
}

func (s *Server) prepareGitGrantPlan(request *grants.Request) (grants.ImmutablePlan, error) {
	createdAt, exists, err := existingGitHubPlanCreatedAt(s.grants, s.plans, request.Client, request.ClientRequestID)
	if err != nil {
		return grants.ImmutablePlan{}, err
	}
	if exists {
		return s.plans.PrepareBindAt(request, createdAt)
	}
	return s.plans.PrepareBind(request)
}

func (s *Server) gitApprovalRequestID(client string, request corepolicy.Request, ruleIDs []string) (string, error) {
	rules := slices.Clone(ruleIDs)
	slices.Sort(rules)
	encoded, err := json.Marshal(struct {
		Request corepolicy.Request `json:"request"`
		Rules   []string           `json:"rules"`
	}{Request: request, Rules: rules})
	if err != nil {
		return "", err
	}
	base := "git-" + plandigest.Digest(encoded)[:48]
	items, err := s.grants.ListForClient(client)
	if err != nil {
		return "", err
	}
	return nextGitApprovalRequestID(base, items), nil
}

func nextGitApprovalRequestID(base string, items []grants.Grant) string {
	var latest grants.Grant
	latestGeneration := 0
	for _, grant := range items {
		generation, ok := gitApprovalRequestGeneration(base, grant.ClientRequestID)
		if !ok || generation < latestGeneration ||
			(generation == latestGeneration && !grant.CreatedAt.After(latest.CreatedAt)) {
			continue
		}
		latest = grant
		latestGeneration = generation
	}
	if latestGeneration == 0 {
		return base
	}
	if latest.Status == grants.StatusPending || latest.Status == grants.StatusActive {
		return latest.ClientRequestID
	}
	return base + "-" + strconv.Itoa(latestGeneration+1)
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
	report, err := gitx.BuildReceivePackRefusal("gh-broker", request, []gitx.ReceivePackFailure{{
		Ref: approval.Ref, Reason: "approval required (" + approval.GrantID + "); approve and retry",
	}})
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "could not render git approval response")
	}
	return c.Blob(http.StatusOK, "application/x-git-receive-pack-result", report)
}
