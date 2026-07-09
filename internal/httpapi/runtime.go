package httpapi

import (
	"context"
	"strings"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
	bktelegram "github.com/osolmaz/brokerkit/notify/telegram"
	"github.com/osolmaz/gh-broker/internal/config"
	"github.com/osolmaz/gh-broker/internal/policy"
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
		ApproveText: "Approve",
		DenyText:    "Deny",
		StatusByAnswer: map[string]string{
			"Grant approved": "Approved. Access is active.",
			"Grant denied":   "Denied. Access was not granted.",
		},
		TerminalStatuses: []string{"Denied. Access was not granted.", "Grant is no longer pending"},
	})
	if err != nil {
		return nil, nil, err
	}
	return telegram, telegram, nil
}

func (s *Server) Start(ctx context.Context) {
	if s.telegram == nil {
		return
	}
	go s.telegram.Poll(ctx, s.handleTelegramDecision)
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
