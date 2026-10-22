package telegram

import (
	"time"

	"github.com/osolmaz/unyolo/approval/view"
	"github.com/osolmaz/unyolo/authorization/budget"
)

// Approval is the bounded semantic content of one approval card. The token
// is the card's own callback token, minted by the owner.
type Approval struct {
	GrantID                  string
	DecisionToken            string
	Broker                   string
	Requester                string
	Operation                string
	Mode                     string
	Reason                   string
	RequestedDurationSeconds int64
	MaxUses                  usebudget.Limit
	PendingExpiresAt         time.Time
	Presentation             approvalview.Presentation
	PresentationUnavailable  bool
}
