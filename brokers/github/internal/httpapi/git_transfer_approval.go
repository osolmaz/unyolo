package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	usebudget "github.com/osolmaz/unyolo/authorization/budget"
	"github.com/osolmaz/unyolo/authorization/grants"
	corepolicy "github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/brokers/github/internal/policy"
)

// authorizeGitTransfer authorizes one Git fetch or LFS request. An allow
// proceeds exactly like authorizeBrokerRequest. A requestable decision
// creates an idempotent operator approval and waits for it while holding the
// Git connection, mirroring the receive-pack approval transaction.
func (s *Server) authorizeGitTransfer(c echo.Context, request policy.Request, run func(echo.Context) error) error {
	handled, err := s.tryAnonymousGitTransfer(c, request, run)
	if handled || err != nil {
		return err
	}
	decision, approvalDecision, err := s.evaluateGitMutation(request)
	if err != nil {
		s.audit(c, request, "error", "could not inspect grants", 0, nil)
		return echo.NewHTTPError(http.StatusInternalServerError, "could not inspect grants")
	}
	if decision.Allowed {
		reserved, reserveErr := s.reserveNativeGrantUse(decision.GrantID)
		if reserveErr != nil {
			s.audit(c, request, "error", "grant is no longer active", 0, decision.MatchedRuleIDs)
			return echo.NewHTTPError(http.StatusConflict, "grant is no longer active")
		}
		return s.runAuthorizedBrokerRequest(c, request, decision, reserved, run)
	}
	if approvalDecision.Effect != policy.EffectRequest || approvalDecision.GrantPolicy == nil {
		s.audit(c, request, outcomeForDecision(decision), decision.Reason, 0, decision.MatchedRuleIDs)
		return echo.NewHTTPError(statusForDecision(decision), decision.Reason)
	}
	return s.runGitTransferApproval(c, request, approvalDecision, run)
}

// runGitTransferApproval requests one operator approval, waits for the
// decision, and proxies the request with the approved grant.
func (s *Server) runGitTransferApproval(c echo.Context, request policy.Request, approvalDecision policy.Decision, run func(echo.Context) error) error {
	if s.notifier == nil && !s.operatorConfigured {
		return echo.NewHTTPError(http.StatusServiceUnavailable, errGitApprovalChannelUnavailable.Error())
	}
	grantRequest, err := s.prepareGitTransferGrantRequest(request, approvalDecision)
	if err != nil {
		return err
	}
	result, err := s.requestGitGrant(grantRequest)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "could not create Git approval")
	}
	plan := grantCreatePlan{request: request, decision: approvalDecision}
	if _, _, err := s.notifyPendingGrant(c, plan, result.Grant.ID); err != nil {
		return err
	}
	s.audit(c, request, "requires_grant", "operator approval requested", 0, approvalDecision.MatchedRuleIDs)
	approved, err := s.waitForGitGrantDecision(c.Request().Context(), result.Grant.ID)
	if err != nil {
		return err
	}
	if approved.Status != grants.StatusActive {
		reason := "approval " + string(approved.Status) + " (" + approved.ID + ")"
		s.audit(c, request, outcomeForDecision(approvalDecision), reason, 0, approvalDecision.MatchedRuleIDs)
		return echo.NewHTTPError(http.StatusForbidden, reason)
	}
	return s.runAuthorizedGitTransfer(c, request, approved.ID, run)
}

// runAuthorizedGitTransfer revalidates policy after approval and proxies the
// request with the new grant, accounting one use.
func (s *Server) runAuthorizedGitTransfer(c echo.Context, request policy.Request, grantID string, run func(echo.Context) error) error {
	revalidated := s.policy.EvaluateGrantRequest(request)
	if revalidated.Effect != policy.EffectRequest || revalidated.GrantPolicy == nil {
		return echo.NewHTTPError(statusForDecision(revalidated), revalidated.Reason)
	}
	granted := policy.Decision{
		Effect: policy.EffectAllow, Allowed: true, Reason: "grant_allowed",
		GrantID: grantID, MatchedRuleIDs: []string{grantID},
	}
	reserved, err := s.reserveNativeGrantUse(grantID)
	if err != nil {
		s.audit(c, request, "error", "grant is no longer active", 0, granted.MatchedRuleIDs)
		return echo.NewHTTPError(http.StatusConflict, "grant is no longer active")
	}
	return s.runAuthorizedBrokerRequest(c, request, granted, reserved, run)
}

// prepareGitTransferGrantRequest builds the idempotent grant request for one
// fetch or LFS approval. The request ID digests the operation, target, and
// rule IDs so discovery, upload-pack, and LFS download share one pending
// approval while git.lfs.write gets its own when a combined rule covers both.
func (s *Server) prepareGitTransferGrantRequest(request policy.Request, decision policy.Decision) (grants.Request, error) {
	duration, pending, mode, maxUses, err := gitTransferApprovalBounds(decision)
	if err != nil {
		return grants.Request{}, echo.NewHTTPError(http.StatusForbidden, err.Error())
	}
	target := policy.CoreTarget(request.Target)
	attrs := map[string][]string{"operation": {string(request.Operation)}}
	requestID, err := s.gitTransactionRequestID(request.Client, target, attrs, decision.MatchedRuleIDs)
	if err != nil {
		return grants.Request{}, err
	}
	return grants.Request{
		Client: request.Client, ClientRequestID: requestID,
		Operation: string(request.Operation), Target: target, Attrs: attrs,
		Metadata: map[string]string{grants.MetadataMode: string(mode)},
		Reason:   gitTransferApprovalReason(request.Operation), Duration: duration, PendingTimeout: pending,
		MaxUses: maxUses, MaxUsesSpecified: true,
	}, nil
}

func gitTransferApprovalBounds(decision policy.Decision) (time.Duration, time.Duration, corepolicy.GrantMode, usebudget.Limit, error) {
	bounds := decision.GrantPolicy
	if bounds == nil {
		return 0, 0, "", 0, errors.New("git approval policy is incompatible with one-use transactions")
	}
	mode := corepolicy.GrantMode(bounds.Mode)
	if mode != corepolicy.GrantModeWindow && mode != corepolicy.GrantModeExecution {
		return 0, 0, "", 0, errors.New("git approval policy has an unsupported mode")
	}
	maxUses := bounds.DefaultMaxUses
	if !maxUses.IsFinite() {
		maxUses = usebudget.Unlimited
	}
	return time.Duration(bounds.DefaultMinutes) * time.Minute,
		time.Duration(bounds.RequestTTLMinutes) * time.Minute, mode, maxUses, nil
}

func gitTransferApprovalReason(operation policy.Operation) string {
	switch operation {
	case policy.OperationGitLFSWrite:
		return "Git LFS write requires approval"
	case policy.OperationGitPushAdvertise:
		return "Git push discovery requires approval"
	default:
		return "Git fetch requires approval"
	}
}
