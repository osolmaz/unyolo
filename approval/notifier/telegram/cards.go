package telegram

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/osolmaz/unyolo/approval/notifier"
)

// Card states. A card is sending until Telegram confirms the message, open
// while its request can still change, and closed once the request is final.
const (
	cardSending = "sending"
	cardOpen    = "open"
	cardClosed  = "closed"
)

// closedCardRetention keeps closed cards long enough to answer late clicks.
const closedCardRetention = 30 * 24 * time.Hour

const cardSchema = `
CREATE TABLE IF NOT EXISTS cards (
  route TEXT NOT NULL,
  request_id TEXT NOT NULL,
  token_digest BLOB NOT NULL,
  chat_id INTEGER NOT NULL,
  message_id INTEGER NOT NULL,
  text TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('sending','open','closed')),
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (route, request_id)
) STRICT;
CREATE TABLE IF NOT EXISTS event_cursors (
  route TEXT PRIMARY KEY,
  cursor TEXT NOT NULL
) STRICT;`

// card is one approval card that the owner sent for a broker request. Only a
// digest of the card's callback token is stored.
type card struct {
	Route       string
	RequestID   string
	TokenDigest []byte
	ChatID      int64
	MessageID   int
	Text        string
	State       string
}

var errCardMismatch = errors.New("telegram callback does not match its approval card")

func (i *Inbox) createCardSchema(ctx context.Context) error {
	if _, err := i.db.ExecContext(ctx, cardSchema); err != nil {
		return fmt.Errorf("initialize telegram cards: %w", err)
	}
	return nil
}

func tokenDigest(token string) []byte {
	digest := sha256.Sum256([]byte(token))
	return digest[:]
}

// reserveCard records a card before it is sent. It returns false when the
// request already has an open or closed card.
func (i *Inbox) reserveCard(ctx context.Context, route, requestID, token, text string) (bool, error) {
	now := i.now().UTC().UnixMilli()
	result, err := i.db.ExecContext(ctx, `INSERT INTO cards
  (route, request_id, token_digest, chat_id, message_id, text, state, updated_at)
  VALUES (?, ?, ?, 0, 0, ?, 'sending', ?)
  ON CONFLICT(route, request_id) DO UPDATE SET token_digest = excluded.token_digest,
    text = excluded.text, updated_at = excluded.updated_at
  WHERE cards.state = 'sending'`, route, requestID, tokenDigest(token), text, now)
	if err != nil {
		return false, fmt.Errorf("reserve telegram card: %w", err)
	}
	rows, err := result.RowsAffected()
	return rows > 0, err
}

func (i *Inbox) openCard(ctx context.Context, route, requestID string, chatID int64, messageID int) error {
	_, err := i.db.ExecContext(ctx, `UPDATE cards SET chat_id = ?, message_id = ?, state = 'open', updated_at = ?
WHERE route = ? AND request_id = ? AND state = 'sending'`, chatID, messageID, i.now().UTC().UnixMilli(), route, requestID)
	return err
}

func (i *Inbox) closeCard(ctx context.Context, route, requestID string) error {
	_, err := i.db.ExecContext(ctx, `UPDATE cards SET state = 'closed', updated_at = ?
WHERE route = ? AND request_id = ? AND state != 'closed'`, i.now().UTC().UnixMilli(), route, requestID)
	return err
}

func (i *Inbox) card(ctx context.Context, route, requestID string) (card, bool, error) {
	value := card{Route: route, RequestID: requestID}
	err := i.db.QueryRowContext(ctx, `SELECT token_digest, chat_id, message_id, text, state FROM cards
WHERE route = ? AND request_id = ?`, route, requestID).Scan(&value.TokenDigest, &value.ChatID, &value.MessageID, &value.Text, &value.State)
	if errors.Is(err, sql.ErrNoRows) {
		return card{}, false, nil
	}
	if err != nil {
		return card{}, false, err
	}
	return value, true, nil
}

// unfinishedCards lists the requests whose cards may still need a send or an
// edit after a restart.
func (i *Inbox) unfinishedCards(ctx context.Context, route string) ([]string, error) {
	rows, err := i.db.QueryContext(ctx, `SELECT request_id FROM cards WHERE route = ? AND state != 'closed'
ORDER BY updated_at`, route)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (i *Inbox) pruneClosedCards(ctx context.Context) error {
	_, err := i.db.ExecContext(ctx, `DELETE FROM cards WHERE state = 'closed' AND updated_at < ?`,
		i.now().UTC().Add(-closedCardRetention).UnixMilli())
	return err
}

func (i *Inbox) eventCursor(ctx context.Context, route string) (string, error) {
	var cursor string
	err := i.db.QueryRowContext(ctx, `SELECT cursor FROM event_cursors WHERE route = ?`, route).Scan(&cursor)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return cursor, err
}

func (i *Inbox) saveEventCursor(ctx context.Context, route, cursor string) error {
	_, err := i.db.ExecContext(ctx, `INSERT INTO event_cursors(route, cursor) VALUES (?, ?)
ON CONFLICT(route) DO UPDATE SET cursor = excluded.cursor`, route, cursor)
	return err
}

func (i *Inbox) clearEventCursor(ctx context.Context, route string) error {
	_, err := i.db.ExecContext(ctx, `DELETE FROM event_cursors WHERE route = ?`, route)
	return err
}

// verifyCard accepts a click only for the open card that the owner sent: the
// same chat and message, the card's own token, and the button label that
// belongs to the clicked action.
func (i *Inbox) verifyCard(ctx context.Context, decision notify.Decision) error {
	value, found, err := i.card(ctx, decision.Route, decision.GrantID)
	if err != nil {
		return err
	}
	if !found || value.State == cardSending || value.ChatID != decision.ChatID || value.MessageID != decision.MessageID {
		return errCardMismatch
	}
	if subtle.ConstantTimeCompare(value.TokenDigest, tokenDigest(decision.DecisionToken)) != 1 {
		return errCardMismatch
	}
	if decision.ButtonText != buttonText(decision.Action) {
		return errCardMismatch
	}
	return nil
}
