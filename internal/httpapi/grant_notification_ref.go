package httpapi

import bknotify "github.com/osolmaz/brokerkit/notify"

func shouldSupersedeNotifier(stored *bknotify.MessageRef, sent bknotify.MessageRef) bool {
	return stored == nil || *stored != sent
}
