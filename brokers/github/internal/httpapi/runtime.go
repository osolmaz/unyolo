package httpapi

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/unyolo/approval"
	"github.com/osolmaz/unyolo/approval/notification"
	unyolotelegram "github.com/osolmaz/unyolo/approval/notifier/telegram"
	"github.com/osolmaz/unyolo/authorization/grants"
	corepolicy "github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/brokers/github/internal/config"
	"github.com/osolmaz/unyolo/brokers/github/internal/policy"
)

const defaultStateDir = "./state"

func stateDir(value string) string {
	if strings.TrimSpace(value) == "" {
		return defaultStateDir
	}
	return value
}

func configuredNotifier(cfg config.Config) (approvalnotify.Notifier, *unyolotelegram.Client, error) {
	if cfg.TelegramBotToken == "" && cfg.TelegramChatID == 0 {
		return nil, nil, nil
	}
	telegram, err := unyolotelegram.NewWithOptions(cfg.TelegramBotToken, cfg.TelegramChatID, nil, "", unyolotelegram.Options{
		Route: unyolotelegram.RouteGitHub,
	})
	if err != nil {
		return nil, nil, err
	}
	return telegram, nil, nil
}

func (s *Server) Start(ctx context.Context) {
	s.startOperationRuntime(ctx)
	s.sealedPayloads.Start(s.lifecycleContext)
	s.startStreamSweeper(s.lifecycleContext)
	s.startTelegram(s.lifecycleContext)
	s.startNotificationSweeper(s.lifecycleContext)
}

func (s *Server) startStreamSweeper(ctx context.Context) {
	s.backgroundWorkers.Add(1)
	go func() {
		defer s.backgroundWorkers.Done()
		_, _ = s.streamStore.SweepExpired(time.Now())
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				_, _ = s.streamStore.SweepExpired(now)
			}
		}
	}()
}

func (s *Server) startTelegram(ctx context.Context) {
	if s.telegram != nil {
		s.backgroundWorkers.Add(1)
		go func() {
			defer s.backgroundWorkers.Done()
			s.telegram.Poll(ctx, s.control.HandleDecision)
		}()
	}
}

func (s *Server) startNotificationSweeper(ctx context.Context) {
	if s.notifier != nil {
		s.backgroundWorkers.Add(1)
		go func() {
			defer s.backgroundWorkers.Done()
			s.runGrantNotificationSweeper(ctx)
		}()
	}
}

func (s *Server) runGrantNotificationSweeper(ctx context.Context) {
	s.deliverGrantStatusUpdates(ctx)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.deliverGrantStatusUpdates(ctx)
		}
	}
}

func (s *Server) deliverGrantStatusUpdates(ctx context.Context) {
	updates, err := s.grants.StatusUpdatesDue()
	if err != nil {
		s.logger.Error("inspect grant notification updates", "error", err)
		return
	}
	for _, update := range updates {
		if update.Grant.Notification == nil {
			continue
		}
		if err := s.notifier.UpdateStatus(ctx, *update.Grant.Notification, approval.StatusForUpdate(update)); err != nil {
			continue
		}
		if err := s.grants.MarkNotificationStatus(update.Grant.ID, update.NotificationStatusKey()); err != nil {
			s.logger.Error("record grant notification update", "error", err)
		}
	}
}

func (s *Server) settleFailedExecution(c echo.Context, reserved []grants.UseReservation, executionErr error) error {
	if !upstreamWasDispatched(c) {
		s.releaseGrantUses(reserved)
		return executionErr
	}
	if retainErr := s.retainGrantUses(reserved); retainErr != nil {
		return errors.Join(executionErr, retainErr)
	}
	return executionErr
}

func (s *Server) evaluateBrokerRequest(request policy.Request) (policy.Decision, error) {
	active, err := s.activePolicyGrantsForRequest(request)
	if err != nil {
		return policy.Decision{}, err
	}
	return s.policy.Evaluate(request, active...), nil
}

func (s *Server) activePolicyGrantsForRequest(request policy.Request) ([]corepolicy.Grant, error) {
	active, err := s.grants.ActivePolicyGrants()
	if err != nil {
		return nil, err
	}
	matched := make([]corepolicy.Grant, 0, len(active))
	for _, candidate := range active {
		grant, getErr := s.grants.Get(candidate.ID)
		if getErr != nil {
			return nil, getErr
		}
		switch grant.Metadata[grants.MetadataMode] {
		case "window":
			matched = append(matched, candidate)
		case "execution":
			if exactGitHubAuthorizationGrant(candidate, request) {
				matched = append(matched, candidate)
			}
		}
	}
	return matched, nil
}

func exactGitHubAuthorizationGrant(grant corepolicy.Grant, request policy.Request) bool {
	return grant.Client == request.Client && grant.Operation == string(request.Operation) &&
		reflect.DeepEqual(grant.Target, policy.CoreTarget(request.Target)) &&
		exactGitHubAuthorizationValues(grant.Attrs, corepolicy.SingletonValues(request.Attrs))
}

func exactGitHubAuthorizationValues(left, right map[string][]string) bool {
	if len(left) != len(right) {
		return false
	}
	for name, values := range left {
		if !reflect.DeepEqual(values, right[name]) {
			return false
		}
	}
	return true
}

func (s *Server) reserveNativeGrantUse(id string) ([]grants.UseReservation, error) {
	if id == "" {
		return nil, nil
	}
	requestIdentity, err := grants.NewUseRequestIdentity()
	if err != nil {
		return nil, err
	}
	return s.reserveGrantUse(id, requestIdentity)
}

func (s *Server) reserveGrantUse(id, requestIdentity string) ([]grants.UseReservation, error) {
	if id == "" {
		return nil, nil
	}
	reservation, err := s.reserveValidatedGrantUse(id, requestIdentity)
	if err != nil {
		return nil, err
	}
	return []grants.UseReservation{reservation}, nil
}

func (s *Server) reserveAuthorizedGrants(authorized []authorizedReceivePackRequest, requestIdentity string) ([]grants.UseReservation, error) {
	seen := map[string]bool{}
	var reserved []grants.UseReservation
	for _, item := range authorized {
		id := item.Decision.GrantID
		if id == "" || seen[id] {
			continue
		}
		reservation, err := s.reserveValidatedGrantUse(id, requestIdentity)
		if err != nil {
			return reserved, err
		}
		seen[id] = true
		reserved = append(reserved, reservation)
	}
	return reserved, nil
}

func (s *Server) reserveValidatedGrantUse(id, requestIdentity string) (grants.UseReservation, error) {
	grant, err := s.grants.Get(id)
	if err != nil {
		return grants.UseReservation{}, err
	}
	if err := s.planValidator.ValidateExecution(grant); err != nil {
		return grants.UseReservation{}, err
	}
	requestID, err := grants.DeriveUseRequestID(id, requestIdentity)
	if err != nil {
		return grants.UseReservation{}, err
	}
	reservation, err := s.grants.ReserveUse(id, requestID, grant.Operation)
	if err != nil || !reservation.Acquired || reservation.Use.State != grants.UseReserved {
		return grants.UseReservation{}, errors.Join(err, grants.ErrUseSettled)
	}
	return reservation, nil
}

func (s *Server) commitGrantUses(reserved []grants.UseReservation) error {
	for _, reservation := range reserved {
		if _, err := s.grants.CommitUse(reservation.Grant.ID, reservation.Use.RequestID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) releaseGrantUses(reserved []grants.UseReservation) {
	for _, reservation := range reserved {
		_, _ = s.grants.ReleaseUse(reservation.Grant.ID, reservation.Use.RequestID)
	}
}

func (s *Server) retainGrantUses(reserved []grants.UseReservation) error {
	var retainedErr error
	for _, reservation := range reserved {
		if _, err := s.grants.RetainUse(reservation.Grant.ID, reservation.Use.RequestID); err != nil {
			retainedErr = errors.Join(retainedErr, err)
		}
	}
	return retainedErr
}

func (s *Server) closeGrantUsesAfterCommitFailure(reserved []grants.UseReservation) error {
	var closeErr error
	for _, reservation := range reserved {
		current, err := s.grants.GetUse(reservation.Grant.ID, reservation.Use.RequestID)
		if err == nil && current.Use.State == grants.UseReserved {
			_, err = s.grants.RetainUse(reservation.Grant.ID, reservation.Use.RequestID)
		}
		if err != nil {
			closeErr = errors.Join(closeErr, err)
		}
	}
	return closeErr
}
