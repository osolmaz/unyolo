package telegram

import (
	"github.com/osolmaz/unyolo/approval/notifier"
)

func parseDecision(update telegramUpdate) (notify.Decision, bool) {
	if update.CallbackQuery == nil {
		return notify.Decision{}, false
	}
	callback := update.CallbackQuery
	route, action, grantID, token, ok := parseCallbackData(callback.Data)
	if !ok {
		return notify.Decision{}, false
	}
	if callback.ID == "" {
		return notify.Decision{}, false
	}
	if callback.Message == nil {
		return notify.Decision{}, false
	}
	if callback.Message.Chat.ID == 0 {
		return notify.Decision{}, false
	}
	if callback.Message.MessageID <= 0 {
		return notify.Decision{}, false
	}
	if callback.Message.Text == "" {
		return notify.Decision{}, false
	}
	return notify.Decision{
		Route:         route,
		Action:        action,
		GrantID:       grantID,
		DecisionToken: token,
		CallbackID:    callback.ID,
		ChatID:        callback.Message.Chat.ID,
		MessageID:     callback.Message.MessageID,
		MessageText:   callback.Message.Text,
		ButtonText:    callback.Message.pressedButtonText(callback.Data),
		OperatorID:    callback.From.ID,
		OperatorTag:   callback.From.Username,
		Approver:      callback.From.Username,
	}, true
}
