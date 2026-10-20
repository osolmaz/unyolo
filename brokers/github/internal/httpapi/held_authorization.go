package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	usebudget "github.com/osolmaz/unyolo/authorization/budget"
	"github.com/osolmaz/unyolo/authorization/grants"
	corepolicy "github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/brokers/github/internal/opcatalog"
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
	held, err := s.authorizeHeld(c, request, "")
	if err != nil {
		return err
	}
	return s.runHeld(c, []heldAuthorization{held}, run)
}

// heldAuthorization is one native request that policy allowed, directly or
// after an operator approval the broker waited for, with its reserved grant
// use.
type heldAuthorization struct {
	request  policy.Request
	decision policy.Decision
	reserved []grants.UseReservation
}

// authorizeHeld authorizes one native request and reserves one grant use. A
// requestable decision creates an idempotent operator approval and holds the
// HTTP request until the operator decides. requestDigest binds an
// execution-mode approval to one exact request; Git transfers pass "".
func (s *Server) authorizeHeld(c echo.Context, request policy.Request, requestDigest string) (heldAuthorization, error) {
	decision, approvalDecision, err := s.evaluateGitMutation(request)
	if err != nil {
		s.audit(c, request, "error", "could not inspect grants", 0, nil)
		return heldAuthorization{}, echo.NewHTTPError(http.StatusInternalServerError, "could not inspect grants")
	}
	if decision.Allowed {
		return s.reserveHeld(c, request, decision)
	}
	if approvalDecision.Effect != policy.EffectRequest || approvalDecision.GrantPolicy == nil {
		s.audit(c, request, outcomeForDecision(decision), decision.Reason, 0, decision.MatchedRuleIDs)
		return heldAuthorization{}, echo.NewHTTPError(statusForDecision(decision), decision.Reason)
	}
	grantID, err := s.waitForHeldApproval(c, request, approvalDecision, requestDigest)
	if err != nil {
		return heldAuthorization{}, err
	}
	revalidated := s.policy.EvaluateGrantRequest(request)
	if revalidated.Effect != policy.EffectRequest || revalidated.GrantPolicy == nil {
		return heldAuthorization{}, echo.NewHTTPError(statusForDecision(revalidated), revalidated.Reason)
	}
	return s.reserveHeld(c, request, policy.Decision{
		Effect: policy.EffectAllow, Allowed: true, Reason: "grant_allowed",
		GrantID: grantID, MatchedRuleIDs: []string{grantID},
	})
}

func (s *Server) reserveHeld(c echo.Context, request policy.Request, decision policy.Decision) (heldAuthorization, error) {
	reserved, err := s.reserveNativeGrantUse(decision.GrantID)
	if err != nil {
		s.audit(c, request, "error", "grant is no longer active", 0, decision.MatchedRuleIDs)
		return heldAuthorization{}, echo.NewHTTPError(http.StatusConflict, "grant is no longer active")
	}
	return heldAuthorization{request: request, decision: decision, reserved: reserved}, nil
}

// waitForHeldApproval requests one operator approval, notifies the operator,
// and waits for the decision. It returns the active grant id.
func (s *Server) waitForHeldApproval(c echo.Context, request policy.Request, approvalDecision policy.Decision, requestDigest string) (string, error) {
	if s.notifier == nil && !s.operatorConfigured {
		return "", echo.NewHTTPError(http.StatusServiceUnavailable, errGitApprovalChannelUnavailable.Error())
	}
	grantRequest, err := s.prepareHeldGrantRequest(request, approvalDecision, requestDigest)
	if err != nil {
		return "", err
	}
	result, err := s.requestGitGrant(grantRequest)
	if err != nil {
		return "", echo.NewHTTPError(http.StatusInternalServerError, "could not create approval")
	}
	plan := grantCreatePlan{request: request, decision: approvalDecision}
	if _, _, err := s.notifyPendingGrant(c, plan, result.Grant.ID); err != nil {
		return "", err
	}
	s.audit(c, request, "requires_grant", "operator approval requested", 0, approvalDecision.MatchedRuleIDs)
	approved, err := s.waitForGitGrantDecision(c.Request().Context(), result.Grant.ID)
	if err != nil {
		return "", err
	}
	if approved.Status != grants.StatusActive {
		reason := "approval " + string(approved.Status) + " (" + approved.ID + ")"
		s.audit(c, request, outcomeForDecision(approvalDecision), reason, 0, approvalDecision.MatchedRuleIDs)
		return "", echo.NewHTTPError(http.StatusForbidden, reason)
	}
	return approved.ID, nil
}

// runHeld runs one upstream call for authorized requests, then commits their
// grant uses or settles them after a failure, and audits every request.
func (s *Server) runHeld(c echo.Context, held []heldAuthorization, run func(echo.Context) error) error {
	var reserved []grants.UseReservation
	for _, item := range held {
		reserved = append(reserved, item.reserved...)
	}
	c.Set(githubOperationContextKey, string(held[0].request.Operation))
	if err := run(c); err != nil {
		err = s.settleFailedExecution(c, reserved, err)
		s.auditHeld(c, held, errorOutcome(err), errorString(err), errorStatus(c, err))
		return err
	}
	if err := s.commitGrantUses(reserved); err != nil {
		_ = s.closeGrantUsesAfterCommitFailure(reserved)
		s.auditHeld(c, held, "error", "grant use commit failed", responseStatus(c))
		return echo.NewHTTPError(http.StatusInternalServerError, "could not commit grant use")
	}
	s.auditHeld(c, held, "proxied", "", responseStatus(c))
	return nil
}

func (s *Server) auditHeld(c echo.Context, held []heldAuthorization, outcome, reason string, status int) {
	for _, item := range held {
		s.audit(c, item.request, outcome, reason, status, item.decision.MatchedRuleIDs)
	}
}

func (s *Server) releaseHeld(held []heldAuthorization) {
	for _, item := range held {
		s.releaseGrantUses(item.reserved)
	}
}

// prepareHeldGrantRequest builds the idempotent grant request for one held
// approval. The request ID digests the operation, target, attributes, and rule
// IDs so retries and follow-up calls share one pending approval, and
// git.lfs.write gets its own when a combined rule covers both. An
// execution-mode approval also binds the exact request digest.
func (s *Server) prepareHeldGrantRequest(request policy.Request, decision policy.Decision, requestDigest string) (grants.Request, error) {
	duration, pending, mode, maxUses, err := gitTransferApprovalBounds(decision)
	if err != nil {
		return grants.Request{}, echo.NewHTTPError(http.StatusForbidden, err.Error())
	}
	target := policy.CoreTarget(request.Target)
	attrs := heldGrantAttrs(request, mode, requestDigest)
	requestID, err := s.gitTransactionRequestID(request.Client, target, attrs, decision.MatchedRuleIDs)
	if err != nil {
		return grants.Request{}, err
	}
	return grants.Request{
		Client: request.Client, ClientRequestID: requestID,
		Operation: string(request.Operation), Target: target, Attrs: attrs,
		Metadata: map[string]string{grants.MetadataMode: string(mode)},
		Reason:   heldApprovalReason(request.Operation), Duration: duration, PendingTimeout: pending,
		MaxUses: maxUses, MaxUsesSpecified: true,
	}, nil
}

func heldGrantAttrs(request policy.Request, mode corepolicy.GrantMode, requestDigest string) map[string][]string {
	attrs := map[string][]string{"operation": {string(request.Operation)}}
	for name, value := range request.Attrs {
		attrs[name] = []string{value}
	}
	if mode == corepolicy.GrantModeExecution && requestDigest != "" {
		attrs["request_digest"] = []string{requestDigest}
	}
	return attrs
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

func heldApprovalReason(operation policy.Operation) string {
	switch operation {
	case policy.OperationGitFetch:
		return "Git fetch requires approval"
	case policy.OperationGitLFSWrite:
		return "Git LFS write requires approval"
	case policy.OperationGitPushAdvertise:
		return "Git push discovery requires approval"
	case policy.OperationGraphQLRead:
		return "GitHub GraphQL read requires approval"
	default:
		if descriptor, found := opcatalog.ByName(string(operation)); found {
			return "GitHub API request requires approval: " + descriptor.Summary
		}
		return "GitHub request requires approval"
	}
}
