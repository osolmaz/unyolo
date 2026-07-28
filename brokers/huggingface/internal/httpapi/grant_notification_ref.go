package httpapi

import unyolonotify "github.com/osolmaz/unyolo/approval/notifier"

func shouldSupersedeNotifier(stored *unyolonotify.MessageRef, sent unyolonotify.MessageRef) bool {
	return stored == nil || *stored != sent
}
