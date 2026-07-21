package telegram

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/osolmaz/brokerkit/approval/notifier"
	_ "modernc.org/sqlite"
)

const (
	callbackRetention  = 24 * time.Hour
	terminalRetention  = 30 * 24 * time.Hour
	maxPendingPerRoute = 32
	maxCallbackRows    = 10_000
)

// Inbox persists Telegram offsets and encrypted callback authority.
type Inbox struct {
	db   *sql.DB
	aead cipher.AEAD
	now  func() time.Time
}

type queuedDecision struct {
	UpdateID   int64
	CallbackID string
	Decision   notify.Decision
	Attempts   int
	Expired    bool
}

// OpenInbox opens the mandatory durable callback inbox.
//
//nolint:cyclop // Initialization deliberately validates each cryptographic and durable-storage boundary in order.
func OpenInbox(ctx context.Context, path string, key []byte) (*Inbox, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("telegram inbox path must be absolute and normalized")
	}
	if len(key) != 32 {
		return nil, errors.New("telegram inbox key must be exactly 32 bytes")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create telegram inbox directory: %w", err)
	}
	if err := ensureInboxFile(path); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	values := url.Values{}
	for _, pragma := range []string{"busy_timeout(5000)", "foreign_keys(ON)", "journal_mode(WAL)", "synchronous(FULL)"} {
		values.Add("_pragma", pragma)
	}
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: values.Encode()}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open telegram inbox: %w", err)
	}
	db.SetMaxOpenConns(1)
	inbox := &Inbox{db: db, aead: aead, now: time.Now}
	if err := inbox.initialize(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return inbox, nil
}

func ensureInboxFile(path string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600) // #nosec G304 -- explicit trusted state path.
	if err == nil {
		return file.Close()
	}
	if !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create telegram inbox: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("telegram inbox must be a private regular file")
	}
	return nil
}

func (i *Inbox) initialize(ctx context.Context) error {
	var version int
	if err := i.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read telegram inbox format: %w", err)
	}
	if version != 0 && version != 1 {
		return fmt.Errorf("unsupported telegram inbox format %d", version)
	}
	const schema = `
CREATE TABLE IF NOT EXISTS metadata (
  key TEXT PRIMARY KEY,
  value INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS callbacks (
  update_id INTEGER PRIMARY KEY,
  callback_id TEXT NOT NULL UNIQUE,
  route TEXT NOT NULL,
  nonce BLOB,
  ciphertext BLOB,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('pending','terminal')),
  terminal_answer TEXT NOT NULL DEFAULT '',
  closed_at INTEGER
) STRICT;
INSERT OR IGNORE INTO metadata(key, value) VALUES ('next_offset', 0);`
	if _, err := i.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("initialize telegram inbox: %w", err)
	}
	if version == 0 {
		if _, err := i.db.ExecContext(ctx, `PRAGMA user_version = 1`); err != nil {
			return fmt.Errorf("initialize telegram inbox format: %w", err)
		}
	}
	return nil
}

// Close closes the durable inbox.
func (i *Inbox) Close() error { return i.db.Close() }

func (i *Inbox) nextOffset(ctx context.Context) (int64, error) {
	return queryInt64(ctx, i.db, `SELECT value FROM metadata WHERE key = 'next_offset'`)
}

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func queryInt64(ctx context.Context, query rowQuerier, statement string, arguments ...any) (int64, error) {
	var value int64
	err := query.QueryRowContext(ctx, statement, arguments...).Scan(&value)
	return value, err
}

func (i *Inbox) persistUpdate(ctx context.Context, updateID int64, decision *notify.Decision) error {
	tx, err := i.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if decision != nil {
		if _, err := tx.ExecContext(ctx, `DELETE FROM callbacks WHERE state = 'terminal' AND closed_at < ?`,
			i.now().UTC().Add(-terminalRetention).UnixMilli()); err != nil {
			return err
		}
		var rows int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM callbacks`).Scan(&rows); err != nil {
			return err
		}
		if rows >= maxCallbackRows {
			return errors.New("telegram callback inbox is full")
		}
		nonce, ciphertext, sealErr := i.seal(*decision, updateID)
		if sealErr != nil {
			return sealErr
		}
		now := i.now().UTC()
		_, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO callbacks
  (update_id, callback_id, route, nonce, ciphertext, next_attempt_at, expires_at, state)
  VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')`, updateID, decision.CallbackID, decision.Route, nonce, ciphertext,
			now.UnixMilli(), now.Add(callbackRetention).UnixMilli())
		clearBytes(ciphertext)
		if err != nil {
			return fmt.Errorf("persist telegram callback: %w", err)
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE metadata SET value = MAX(value, ?) WHERE key = 'next_offset'`, updateID+1)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (i *Inbox) seal(decision notify.Decision, updateID int64) ([]byte, []byte, error) {
	plaintext, err := json.Marshal(decision)
	if err != nil {
		return nil, nil, err
	}
	defer clearBytes(plaintext)
	nonce := make([]byte, i.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generate telegram inbox nonce: %w", err)
	}
	aad := []byte(fmt.Sprintf("brokerkit-telegram:%d", updateID))
	return nonce, i.aead.Seal(nil, nonce, plaintext, aad), nil
}

func (i *Inbox) open(updateID int64, nonce, ciphertext []byte) (notify.Decision, error) {
	aad := []byte(fmt.Sprintf("brokerkit-telegram:%d", updateID))
	plaintext, err := i.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return notify.Decision{}, errors.New("telegram callback authority cannot be decrypted")
	}
	defer clearBytes(plaintext)
	var decision notify.Decision
	if err := json.Unmarshal(plaintext, &decision); err != nil {
		return notify.Decision{}, errors.New("telegram callback authority is invalid")
	}
	return decision, nil
}

func (i *Inbox) pending(ctx context.Context) ([]queuedDecision, error) {
	now := i.now().UTC().UnixMilli()
	rows, err := i.db.QueryContext(ctx, `SELECT update_id, callback_id, nonce, ciphertext, attempts, expires_at
FROM (
  SELECT update_id, callback_id, route, nonce, ciphertext, attempts, expires_at, next_attempt_at,
         ROW_NUMBER() OVER (PARTITION BY route ORDER BY next_attempt_at, update_id) AS route_row
  FROM callbacks WHERE state = 'pending' AND next_attempt_at <= ?
)
WHERE route_row <= ? ORDER BY next_attempt_at, update_id`, now, maxPendingPerRoute)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var result []queuedDecision
	for rows.Next() {
		var item queuedDecision
		var nonce, ciphertext []byte
		var expiresAt int64
		if err := rows.Scan(&item.UpdateID, &item.CallbackID, &nonce, &ciphertext, &item.Attempts, &expiresAt); err != nil {
			return nil, err
		}
		decision, err := i.open(item.UpdateID, nonce, ciphertext)
		clearBytes(ciphertext)
		if err != nil {
			return nil, err
		}
		item.Decision = decision
		item.Expired = expiresAt <= now
		result = append(result, item)
	}
	return result, rows.Err()
}

func (i *Inbox) retry(ctx context.Context, item queuedDecision) error {
	delay := retryBackoff(item.Attempts + 1)
	_, err := i.db.ExecContext(ctx, `UPDATE callbacks SET attempts = attempts + 1, next_attempt_at = ?
WHERE update_id = ? AND state = 'pending'`, i.now().UTC().Add(delay).UnixMilli(), item.UpdateID)
	return err
}

func retryBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 8 {
		attempt = 8
	}
	return time.Duration(1<<(attempt-1)) * time.Second
}

func (i *Inbox) terminal(ctx context.Context, item queuedDecision, answer notify.Answer) error {
	_, err := i.db.ExecContext(ctx, `UPDATE callbacks SET state = 'terminal', terminal_answer = ?,
	nonce = NULL, ciphertext = NULL, closed_at = ? WHERE update_id = ?`, answer, i.now().UTC().UnixMilli(), item.UpdateID)
	return err
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
