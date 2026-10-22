package telegram

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/osolmaz/unyolo/approval/notifier"
	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/operator/client"
	"github.com/osolmaz/unyolo/operator/v1"
)

const (
	ownerRetryDelay = 5 * time.Second
	cardTokenBytes  = 12
)

// CardSource is the trusted Operator V1 surface that the owner follows for one
// broker: its request list, its event stream, and its decisions.
type CardSource interface {
	OperatorSource
	List(context.Context, operatorv1.Query) (operatorv1.Page, error)
	Watch(context.Context, string) (operatorv1.EventStream, error)
}

// Owner sends and updates the approval cards of every broker route. It is the
// only component that writes unYOLO approval messages to Telegram.
type Owner struct {
	client     *Client
	inbox      *Inbox
	routes     map[string]CardSource
	retryDelay time.Duration
	newToken   func() (string, error)
}

// NewOwner builds the card owner for the configured broker routes.
func NewOwner(client *Client, inbox *Inbox, routes map[string]CardSource) (*Owner, error) {
	if client == nil || inbox == nil || len(routes) == 0 {
		return nil, errors.New("telegram card owner requires a client, an inbox, and at least one route")
	}
	cloned := make(map[string]CardSource, len(routes))
	for route, source := range routes {
		if !validRoute(route) || routeBrokerNames[route] == "" || source == nil {
			return nil, fmt.Errorf("telegram card owner route %q is invalid", route)
		}
		cloned[route] = source
	}
	return &Owner{client: client, inbox: inbox, routes: cloned, retryDelay: ownerRetryDelay, newToken: newCardToken}, nil
}

func newCardToken() (string, error) {
	data := make([]byte, cardTokenBytes)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("generate telegram card token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// Run follows every route until ctx ends. A failing route retries on its own
// and does not stop the others.
func (o *Owner) Run(ctx context.Context) error {
	var group sync.WaitGroup
	for route, source := range o.routes {
		group.Add(1)
		go func() {
			defer group.Done()
			o.runRoute(ctx, route, source)
		}()
	}
	group.Wait()
	return ctx.Err()
}

func (o *Owner) runRoute(ctx context.Context, route string, source CardSource) {
	for ctx.Err() == nil {
		if err := o.follow(ctx, route, source); err != nil {
			wait(ctx, o.retryDelay)
		}
	}
}

// follow applies events from the stored cursor. Without a cursor, or after
// the broker dropped it, it first rebuilds the cards from a fresh list.
func (o *Owner) follow(ctx context.Context, route string, source CardSource) error {
	cursor, err := o.inbox.eventCursor(ctx, route)
	if err != nil {
		return err
	}
	if cursor == "" {
		if cursor, err = o.resync(ctx, route, source); err != nil {
			return err
		}
	}
	stream, err := source.Watch(ctx, cursor)
	if cursorExpired(err) {
		return o.inbox.clearEventCursor(ctx, route)
	}
	if err != nil {
		return err
	}
	defer func() { _ = stream.Close() }()
	for {
		event, err := stream.Receive(ctx)
		if err != nil {
			return err
		}
		if err := o.apply(ctx, route, source, event.RequestID); err != nil {
			return err
		}
		if err := o.inbox.saveEventCursor(ctx, route, event.Cursor); err != nil {
			return err
		}
	}
}

func cursorExpired(err error) bool {
	var apiError *operatorclient.Error
	return errors.As(err, &apiError) && apiError.Code == "cursor_expired"
}

// resync sends cards for every pending request, settles every unfinished card,
// and returns the event cursor that continues after the listed state.
func (o *Owner) resync(ctx context.Context, route string, source CardSource) (string, error) {
	eventCursor := ""
	query := operatorv1.Query{Status: grants.StatusGroupPending}
	for {
		page, err := source.List(ctx, query)
		if err != nil {
			return "", err
		}
		if eventCursor == "" {
			eventCursor = page.EventCursor
		}
		for _, request := range page.Requests {
			if err := o.applyRequest(ctx, route, request); err != nil {
				return "", err
			}
		}
		if page.NextCursor == "" {
			break
		}
		query.Cursor = page.NextCursor
	}
	if eventCursor == "" {
		return "", errors.New("operator request list has no event cursor")
	}
	if err := o.settleUnfinished(ctx, route, source); err != nil {
		return "", err
	}
	return eventCursor, o.inbox.saveEventCursor(ctx, route, eventCursor)
}

func (o *Owner) settleUnfinished(ctx context.Context, route string, source CardSource) error {
	ids, err := o.inbox.unfinishedCards(ctx, route)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := o.apply(ctx, route, source, id); err != nil {
			return err
		}
	}
	return o.inbox.pruneClosedCards(ctx)
}

func (o *Owner) apply(ctx context.Context, route string, source CardSource, requestID string) error {
	request, err := source.Get(ctx, requestID)
	var apiError *operatorclient.Error
	if errors.As(err, &apiError) && apiError.Status == http.StatusNotFound {
		return o.closeMissing(ctx, route, requestID)
	}
	if err != nil {
		return err
	}
	return o.applyRequest(ctx, route, request)
}

// applyRequest makes one card match its request: a pending request gets a
// card, and a decided request gets its status on the card.
func (o *Owner) applyRequest(ctx context.Context, route string, request operatorv1.Request) error {
	existing, found, err := o.inbox.card(ctx, route, request.ID)
	if err != nil {
		return err
	}
	switch {
	case request.Status == grants.StatusPending:
		if found && existing.State != cardSending {
			return nil
		}
		return o.send(ctx, route, request)
	case !found || existing.State == cardClosed:
		return nil
	case existing.State == cardSending:
		return o.inbox.closeCard(ctx, route, request.ID)
	default:
		return o.updateCard(ctx, existing, statusForRequest(request), finalStatus(request.Status))
	}
}

func (o *Owner) send(ctx context.Context, route string, request operatorv1.Request) error {
	token, err := o.newToken()
	if err != nil {
		return err
	}
	semantic, err := semanticApproval(request, route, token)
	if err != nil {
		return err
	}
	text, err := RenderApproval(semantic)
	if err != nil {
		return err
	}
	reserved, err := o.inbox.reserveCard(ctx, route, request.ID, token, text)
	if err != nil || !reserved {
		return err
	}
	ref, err := o.client.sendCard(ctx, route, semantic)
	if err != nil {
		return err
	}
	return o.inbox.openCard(ctx, route, request.ID, ref.ChatID, ref.MessageID)
}

func (o *Owner) updateCard(ctx context.Context, existing card, status notify.Status, final bool) error {
	ref := notify.MessageRef{ChatID: existing.ChatID, MessageID: existing.MessageID, Text: existing.Text}
	if err := o.client.UpdateStatus(ctx, ref, status); err != nil {
		return err
	}
	if !final {
		return nil
	}
	return o.inbox.closeCard(ctx, existing.Route, existing.RequestID)
}

func (o *Owner) closeMissing(ctx context.Context, route, requestID string) error {
	existing, found, err := o.inbox.card(ctx, route, requestID)
	if err != nil || !found || existing.State == cardClosed {
		return err
	}
	if existing.State == cardSending {
		return o.inbox.closeCard(ctx, route, requestID)
	}
	return o.updateCard(ctx, existing, notify.Status{Kind: notify.StatusUnavailable}, true)
}

// finalStatus reports whether a request can no longer change.
func finalStatus(status grants.Status) bool {
	return status != grants.StatusPending && status != grants.StatusActive
}
