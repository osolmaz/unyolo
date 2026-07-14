package httpapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/osolmaz/brokerkit/brokers/github/internal/config"
	"github.com/osolmaz/brokerkit/brokers/github/internal/policy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
	bktelegram "github.com/osolmaz/brokerkit/notify/telegram"
)

const defaultStateDir = "./state"

func stateDir(value string) string {
	if strings.TrimSpace(value) == "" {
		return defaultStateDir
	}
	return value
}

func configuredNotifier(cfg config.Config) (notify.Notifier, *bktelegram.Client, error) {
	if cfg.TelegramBotToken == "" && cfg.TelegramChatID == 0 {
		return nil, nil, nil
	}
	telegram, err := bktelegram.NewWithOptions(cfg.TelegramBotToken, cfg.TelegramChatID, nil, "", bktelegram.Options{
		IgnoredAnswer: "Grant decision ignored",
		ApproveText:   "Approve",
		DenyText:      "Deny",
	})
	if err != nil {
		return nil, nil, err
	}
	return telegram, telegram, nil
}

func (s *Server) Start(ctx context.Context) {
	s.startOperationWorker(ctx)
	s.sealedPayloads.Start(s.lifecycleContext)
	s.startStreamSweeper(s.lifecycleContext)
	s.startTelegram(ctx)
	s.startNotificationSweeper(ctx)
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
		go s.telegram.Poll(ctx, s.control.HandleDecision)
	}
}

func (s *Server) startNotificationSweeper(ctx context.Context) {
	if s.notifier != nil {
		go s.runGrantNotificationSweeper(ctx)
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
		if err := s.notifier.UpdateStatus(ctx, *update.Grant.Notification, grantStatusText(update)); err != nil {
			continue
		}
		if err := s.grants.MarkNotificationStatus(update.Grant.ID, update.NotificationStatusKey()); err != nil {
			s.logger.Error("record grant notification update", "error", err)
		}
	}
}

func grantStatusText(update grants.StatusUpdate) string {
	switch update.Kind {
	case grants.StatusUpdateRetainedReservation:
		return "Result is ambiguous. Access is closed until an operator reviews the retained use."
	case grants.StatusUpdateUsed, grants.StatusUpdateUsedExpired:
		return grantUseStatusText(update.Grant)
	default:
		return grantLifecycleStatusText(update.Status)
	}
}

func grantLifecycleStatusText(status grants.Status) string {
	switch status {
	case grants.StatusActive:
		return "Approved. Access is active."
	case grants.StatusDenied:
		return "Denied. Access was not granted."
	case grants.StatusExpired:
		return "Expired. Access is closed."
	case grants.StatusConsumed:
		return "Used. Access is now closed."
	case grants.StatusRevoked:
		return "Revoked. Access is closed."
	case grants.StatusCanceled:
		return "Canceled. Approval request is closed."
	default:
		return "Grant status changed."
	}
}

func grantUseStatusText(grant grants.Grant) string {
	remaining, finite := grant.MaxUses.Remaining(grant.UsedCount, 0)
	if !finite {
		return fmt.Sprintf("Used %d times. Access remains active until expiry.", grant.UsedCount)
	}
	if grant.Status != grants.StatusActive || grant.ReservationRetained || remaining <= 0 {
		return "Used. Access is now closed."
	}
	return fmt.Sprintf("Used %d of %d. %d uses remain.", grant.UsedCount, int(grant.MaxUses), remaining)
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
	grant, err := s.grants.ReserveUse(id)
	if err != nil {
		return nil, err
	}
	if err := s.planValidator.ValidateExecution(grant); err != nil {
		_, _ = s.grants.ReleaseUse(grant.ID)
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
		grant, err := s.grants.ReserveUse(id)
		if err != nil {
			return reserved, err
		}
		if err := s.planValidator.ValidateExecution(grant); err != nil {
			_, _ = s.grants.ReleaseUse(grant.ID)
			return reserved, err
		}
		seen[id] = true
		reserved = append(reserved, grant)
	}
	return reserved, nil
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
