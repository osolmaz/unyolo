package httpapi

import (
	bknotify "github.com/osolmaz/brokerkit/notify"
	"github.com/osolmaz/hf-broker/internal/grants"
)

func shouldSupersedeNotifier(stored *grants.NotifierMessage, sent bknotify.MessageRef) bool {
	return stored == nil || *stored != sent
}
