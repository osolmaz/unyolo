package httpapi

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/unyolo/approval"
	"github.com/osolmaz/unyolo/approval/notification"
	unyolotelegram "github.com/osolmaz/unyolo/approval/notifier/telegram"
	"github.com/osolmaz/unyolo/authorization/grants"
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

func (s *Server) settleFailedExecution(c echo.Context, reserved []grants.Grant, executionErr error) error {
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
	active, err := s.grants.ActivePolicyGrants()
	if err != nil {
		return policy.Decision{}, err
	}
	return s.policy.Evaluate(request, active...), nil
}

func (s *Server) reserveGrantUse(id string) ([]grants.Grant, error) {
	if id == "" {
		return nil, nil
	}
	grant, err := s.reserveValidatedGrantUse(id)
	if err != nil {
		return nil, err
	}
	return []grants.Grant{grant}, nil
}

func (s *Server) reserveAuthorizedGrants(authorized []authorizedReceivePackRequest) ([]grants.Grant, error) {
	seen := map[string]bool{}
	var reserved []grants.Grant
	for _, item := range authorized {
		id := item.Decision.GrantID
		if id == "" || seen[id] {
			continue
		}
		grant, err := s.reserveValidatedGrantUse(id)
		if err != nil {
			return reserved, err
		}
		seen[id] = true
		reserved = append(reserved, grant)
	}
	return reserved, nil
}

func (s *Server) reserveValidatedGrantUse(id string) (grants.Grant, error) {
	grant, err := s.grants.ReserveUse(id)
	if err != nil {
		return grants.Grant{}, err
	}
	if err := s.planValidator.ValidateExecution(grant); err != nil {
		_, _ = s.grants.ReleaseUse(grant.ID)
		return grants.Grant{}, err
	}
	return grant, nil
}

func (s *Server) commitGrantUses(reserved []grants.Grant) error {
	for _, grant := range reserved {
		if _, err := s.grants.CommitUse(grant.ID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) releaseGrantUses(reserved []grants.Grant) {
	for _, grant := range reserved {
		_, _ = s.grants.ReleaseUse(grant.ID)
	}
}

func (s *Server) retainGrantUses(reserved []grants.Grant) error {
	var retainedErr error
	for _, grant := range reserved {
		if err := s.retainGrantUse(grant.ID); err != nil {
			retainedErr = errors.Join(retainedErr, err)
		}
	}
	return retainedErr
}

func (s *Server) retainGrantUse(id string) error {
	grant, err := s.grants.RetainUse(id)
	if err != nil {
		return err
	}
	if grant.Status != grants.StatusActive {
		return nil
	}
	_, err = s.grants.Revoke(id, "broker:ambiguous-upstream-result")
	return err
}

func (s *Server) closeGrantUsesAfterCommitFailure(reserved []grants.Grant) error {
	var closeErr error
	for _, reservedGrant := range reserved {
		grant, err := s.grants.Get(reservedGrant.ID)
		if err != nil {
			closeErr = errors.Join(closeErr, err)
			continue
		}
		switch {
		case grant.ReservedCount > 0:
			err = s.retainGrantUse(grant.ID)
		case grant.Status == grants.StatusActive:
			_, err = s.grants.Revoke(grant.ID, "broker:ambiguous-commit")
		}
		if err != nil {
			closeErr = errors.Join(closeErr, err)
		}
	}
	return closeErr
}
