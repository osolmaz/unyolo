package httpapi

import bknotify "github.com/osolmaz/brokerkit/approval/notifier"

func shouldSupersedeNotifier(stored *bknotify.MessageRef, sent bknotify.MessageRef) bool {
	return stored == nil || *stored != sent
}
