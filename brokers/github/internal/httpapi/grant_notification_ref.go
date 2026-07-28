package httpapi

import "github.com/osolmaz/unyolo/approval/notifier"

func shouldSupersedeNotification(stored *notify.MessageRef, sent notify.MessageRef) bool {
	return stored == nil || *stored != sent
}
