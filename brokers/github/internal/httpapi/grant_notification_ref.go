package httpapi

import "github.com/osolmaz/brokerkit/approval/notifier"

func shouldSupersedeNotification(stored *notify.MessageRef, sent notify.MessageRef) bool {
	return stored == nil || *stored != sent
}
