package githubauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/osolmaz/brokerkit/credential/store"
	"github.com/osolmaz/brokerkit/internal/strictjson"
)

const (
	userCredentialKind      = "github-app-user-token" // #nosec G101 -- encrypted credential record kind, not a credential.
	maxOAuthBodyBytes       = 64 * 1024
	userCredentialNamespace = "github-users" // #nosec G101 -- storage namespace, not a credential.
)

// OpenUserCredentialStore opens the broker-owned namespace reserved for
// internal GitHub App user credentials.
func OpenUserCredentialStore(stateDir string) (*credentialstore.Store, error) {
	return credentialstore.OpenNamespace(stateDir, userCredentialNamespace)
}

// UserCredentialStorePath returns the state subtree whose ownership the local
// setup command must preserve for the broker service account.
func UserCredentialStorePath(stateDir string) (string, error) {
	return credentialstore.NamespacePath(stateDir, userCredentialNamespace)
}

type UserEnrollment struct {
	UserID           int64     `json:"user_id"`
	Login            string    `json:"login"`
	AccessToken      []byte    `json:"access_token"`
	RefreshToken     []byte    `json:"refresh_token"`
	AccessExpiresAt  time.Time `json:"access_expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

type storedUserCredential = UserEnrollment

// StoredUserCredentialStatus is secret-safe metadata for one encrypted user
// credential. It contains no login or credential value.
type StoredUserCredentialStatus struct {
	UserID           int64
	UpdatedAt        time.Time
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
}

// InspectStoredUserCredentials opens the existing user namespace read-only and
// returns only lifecycle metadata.
func InspectStoredUserCredentials(stateDir string) ([]StoredUserCredentialStatus, error) {
	store, err := credentialstore.OpenNamespaceExisting(stateDir, userCredentialNamespace)
	if err != nil {
		return nil, err
	}
	metadata, err := store.ListMetadata(userCredentialKind)
	if err != nil {
		return nil, err
	}
	result := make([]StoredUserCredentialStatus, 0, len(metadata))
	for _, item := range metadata {
		status, decodeErr := storedUserStatus(store, item)
		if decodeErr != nil {
			return nil, decodeErr
		}
		result = append(result, status)
	}
	return result, nil
}

func storedUserStatus(store *credentialstore.Store, metadata credentialstore.Metadata) (StoredUserCredentialStatus, error) {
	encoded, _, err := store.Get(metadata.Slot, userCredentialKind)
	if err != nil {
		return StoredUserCredentialStatus{}, errors.New("GitHub user credential metadata is unavailable")
	}
	defer zero(encoded)
	var value storedUserCredential
	if strictjson.Decode(encoded, &value, true) != nil || metadata.Slot != userSlot(value.UserID) ||
		value.UserID <= 0 || value.AccessExpiresAt.IsZero() || !value.RefreshExpiresAt.After(value.AccessExpiresAt) {
		zeroStored(&value)
		return StoredUserCredentialStatus{}, errors.New("GitHub user credential metadata is invalid")
	}
	status := StoredUserCredentialStatus{UserID: value.UserID, UpdatedAt: metadata.UpdatedAt.UTC(),
		AccessExpiresAt: value.AccessExpiresAt.UTC(), RefreshExpiresAt: value.RefreshExpiresAt.UTC()}
	zeroStored(&value)
	return status, nil
}

type refreshPayload struct {
	AccessToken           string `json:"access_token"`
	ExpiresIn             int64  `json:"expires_in"`
	RefreshToken          string `json:"refresh_token"`
	RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in"`
	TokenType             string `json:"token_type"`
}

type userProvider struct {
	store         *credentialstore.Store
	apiURL        *url.URL
	oauthURL      *url.URL
	client        *http.Client
	clientID      string
	clientSecret  []byte
	now           func() time.Time
	refreshBefore time.Duration
	mu            sync.Mutex
	locks         sync.Map
	generation    map[int64]uint64
	active        map[int64]*Credential
}

func newUserProvider(store *credentialstore.Store, apiURL, webURL *url.URL, client *http.Client, clientID string, clientSecret []byte, now func() time.Time, refreshBefore time.Duration) *userProvider {
	if now == nil {
		now = time.Now
	}
	if refreshBefore <= 0 {
		refreshBefore = defaultRefreshBefore
	}
	return &userProvider{store: store, apiURL: apiURL, oauthURL: webURL.JoinPath("login", "oauth", "access_token"), client: client,
		clientID: strings.TrimSpace(clientID), clientSecret: append([]byte(nil), clientSecret...), now: now, refreshBefore: refreshBefore,
		generation: map[int64]uint64{}, active: map[int64]*Credential{}}
}

func (p *userProvider) enroll(ctx context.Context, enrollment UserEnrollment, rotate bool) error {
	unlock := p.lockUser(enrollment.UserID)
	defer unlock()
	if err := p.validateEnrollment(enrollment); err != nil {
		return err
	}
	generation := p.userGeneration(enrollment.UserID)
	if err := p.validateEnrollmentMode(enrollment.UserID, rotate); err != nil {
		return err
	}
	if err := p.verifyUser(ctx, enrollment); err != nil {
		return err
	}
	old, err := p.rotationRecord(enrollment.UserID, rotate)
	if err != nil {
		return err
	}
	if err := p.storeRecordIfCurrent(enrollment, generation); err != nil {
		return err
	}
	return p.finalizeEnrollmentRotation(ctx, enrollment, old, generation, rotate)
}

func (p *userProvider) validateEnrollmentMode(userID int64, rotate bool) error {
	exists := p.store.Exists(userSlot(userID))
	if exists == rotate {
		return nil
	}
	if rotate {
		return errors.New("GitHub user credential is not enrolled")
	}
	return errors.New("GitHub user credential is already enrolled")
}

func (p *userProvider) rotationRecord(userID int64, rotate bool) (storedUserCredential, error) {
	if !rotate {
		return storedUserCredential{}, nil
	}
	return p.load(userID)
}

func (p *userProvider) finalizeEnrollmentRotation(ctx context.Context, enrollment UserEnrollment, old storedUserCredential, generation uint64, rotate bool) error {
	if !rotate {
		return nil
	}
	defer zeroStored(&old)
	if err := p.revokeToken(ctx, old.AccessToken); err != nil {
		return p.rollbackEnrollmentRotation(ctx, old, enrollment, generation, err)
	}
	return nil
}

func (p *userProvider) rollbackEnrollmentRotation(ctx context.Context, old, enrollment UserEnrollment, generation uint64, err error) error {
	// Keep rotation atomic from the operator's perspective: restore the
	// still-valid old record and revoke the replacement best-effort.
	_ = p.storeRecordIfCurrent(old, generation)
	_ = p.revokeToken(ctx, enrollment.AccessToken)
	return err
}

func (p *userProvider) credential(ctx context.Context, userID int64) (*Credential, error) {
	if userID <= 0 {
		return nil, errors.New("GitHub user id is invalid")
	}
	unlock := p.lockUser(userID)
	defer unlock()
	generation := p.userGeneration(userID)
	record, cached, err := p.currentUserRecord(ctx, userID, generation)
	if err != nil {
		return nil, err
	}
	if cached != nil {
		return cached, nil
	}
	defer zeroStored(&record)
	credential := &Credential{metadata: Metadata{Kind: KindUser, UserID: userID, APIHost: p.apiURL.Host, ExpiresAt: record.AccessExpiresAt.UTC()},
		token: append([]byte(nil), record.AccessToken...)}
	if err := p.activate(userID, generation, credential); err != nil {
		credential.invalidate()
		return nil, err
	}
	return credential, nil
}

func (p *userProvider) currentUserRecord(ctx context.Context, userID int64, generation uint64) (storedUserCredential, *Credential, error) {
	record, err := p.load(userID)
	if err != nil {
		return storedUserCredential{}, nil, err
	}
	now := p.now().UTC()
	if record.AccessExpiresAt.After(now.Add(p.refreshBefore)) {
		if credential := p.activeCredential(userID, record.AccessExpiresAt); credential != nil {
			zeroStored(&record)
			return storedUserCredential{}, credential, nil
		}
	}
	if !record.AccessExpiresAt.After(now.Add(p.refreshBefore)) {
		record, err = p.refreshAndStore(ctx, record, generation)
		if err != nil {
			return storedUserCredential{}, nil, err
		}
	}
	return record, nil, nil
}

func (p *userProvider) refreshAndStore(ctx context.Context, record storedUserCredential, generation uint64) (storedUserCredential, error) {
	refreshed, err := p.refresh(ctx, record)
	zeroStored(&record)
	if err != nil {
		return storedUserCredential{}, err
	}
	if err := p.storeRecordIfCurrent(refreshed, generation); err != nil {
		_ = p.revokeToken(context.WithoutCancel(ctx), refreshed.AccessToken)
		zeroStored(&refreshed)
		return storedUserCredential{}, err
	}
	return refreshed, nil
}

func (p *userProvider) refresh(ctx context.Context, old storedUserCredential) (storedUserCredential, error) {
	now := p.now().UTC()
	if p.clientID == "" || len(p.clientSecret) == 0 || len(old.RefreshToken) == 0 || !old.RefreshExpiresAt.After(now.Add(p.refreshBefore)) {
		return storedUserCredential{}, errors.New("GitHub user credential cannot be refreshed")
	}
	payload, err := p.requestRefresh(ctx, old.RefreshToken)
	if err != nil {
		return storedUserCredential{}, err
	}
	result := storedUserCredential{UserID: old.UserID, Login: old.Login, AccessToken: []byte(payload.AccessToken), RefreshToken: []byte(payload.RefreshToken),
		AccessExpiresAt: now.Add(time.Duration(payload.ExpiresIn) * time.Second), RefreshExpiresAt: now.Add(time.Duration(payload.RefreshTokenExpiresIn) * time.Second)}
	return result, nil
}

func (p *userProvider) requestRefresh(ctx context.Context, refreshToken []byte) (refreshPayload, error) {
	request, err := p.newRefreshRequest(ctx, refreshToken)
	if err != nil {
		return refreshPayload{}, err
	}
	response, err := p.client.Do(request)
	if err != nil {
		return refreshPayload{}, APIError{Code: "unavailable"}
	}
	defer func() { _ = response.Body.Close() }()
	return decodeRefreshResponse(response)
}

func (p *userProvider) newRefreshRequest(ctx context.Context, refreshToken []byte) (*http.Request, error) {
	form := url.Values{
		"client_id": {p.clientID}, "client_secret": {string(p.clientSecret)}, "grant_type": {"refresh_token"}, "refresh_token": {string(refreshToken)},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.oauthURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errors.New("create GitHub user credential refresh request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return request, nil
}

func decodeRefreshResponse(response *http.Response) (refreshPayload, error) {
	data, err := io.ReadAll(io.LimitReader(response.Body, maxOAuthBodyBytes+1))
	if err != nil || len(data) > maxOAuthBodyBytes || response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return refreshPayload{}, APIError{Code: statusCodeName(response.StatusCode), StatusCode: response.StatusCode}
	}
	return decodeRefreshPayload(data)
}

func decodeRefreshPayload(data []byte) (refreshPayload, error) {
	var payload refreshPayload
	if err := strictjson.Decode(data, &payload, false); err != nil || !validRefreshPayload(payload) {
		return refreshPayload{}, errors.New("GitHub user credential refresh response is invalid")
	}
	return payload, nil
}

func validRefreshPayload(payload refreshPayload) bool {
	return payload.AccessToken != "" && payload.RefreshToken != "" && payload.ExpiresIn > 0 && payload.RefreshTokenExpiresIn > 0 && strings.EqualFold(payload.TokenType, "bearer")
}

func (p *userProvider) revoke(ctx context.Context, userID int64) error {
	unlock := p.lockUser(userID)
	defer unlock()
	record, err := p.load(userID)
	if err != nil {
		return err
	}
	defer zeroStored(&record)
	if err := p.revokeToken(ctx, record.AccessToken); err != nil && !IsNotFound(err) {
		return err
	}
	return p.invalidateLocked(userID)
}

func (p *userProvider) revokeToken(ctx context.Context, token []byte) error {
	if p.clientID == "" || len(p.clientSecret) == 0 {
		return errors.New("GitHub App client credential is unavailable")
	}
	basicClient := cloneHTTPClient(p.client, basicAuthTransport{base: transport(p.client), username: p.clientID, password: p.clientSecret})
	sdk, err := newGitHubClient(basicClient, p.apiURL, nil)
	if err != nil {
		return errors.New("initialize GitHub user revocation client")
	}
	_, err = sdk.Authorizations.Revoke(ctx, p.clientID, string(token))
	return classifyAPIError(err)
}

func (p *userProvider) invalidate(userID int64) error {
	if userID <= 0 {
		return errors.New("GitHub user id is invalid")
	}
	unlock := p.lockUser(userID)
	defer unlock()
	return p.invalidateLocked(userID)
}

func (p *userProvider) invalidateLocked(userID int64) error {
	p.mu.Lock()
	p.generation[userID]++
	p.clearActiveLocked(userID)
	p.mu.Unlock()
	return p.store.Delete(userSlot(userID))
}

func (p *userProvider) validateEnrollment(value UserEnrollment) error {
	now := p.now().UTC()
	if value.UserID <= 0 || strings.TrimSpace(value.Login) == "" || len(value.AccessToken) == 0 || len(value.RefreshToken) == 0 ||
		!value.AccessExpiresAt.After(now.Add(p.refreshBefore)) || !value.RefreshExpiresAt.After(value.AccessExpiresAt) {
		return errors.New("GitHub user enrollment is invalid or not expiring")
	}
	return nil
}

func (p *userProvider) verifyUser(ctx context.Context, enrollment UserEnrollment) error {
	sdk, err := newGitHubClient(p.client, p.apiURL, enrollment.AccessToken)
	if err != nil {
		return errors.New("initialize GitHub user verification client")
	}
	user, _, err := sdk.Users.Get(ctx, "")
	if err != nil {
		return classifyAPIError(err)
	}
	if user.GetID() != enrollment.UserID || !strings.EqualFold(user.GetLogin(), enrollment.Login) {
		return errors.New("GitHub user enrollment identity does not match")
	}
	return nil
}

func (p *userProvider) storeRecord(value storedUserCredential) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return errors.New("encode GitHub user credential")
	}
	defer zero(encoded)
	_, err = p.store.Put(userSlot(value.UserID), userCredentialKind, encoded)
	if err != nil {
		return errors.New("store GitHub user credential")
	}
	return nil
}

func (p *userProvider) storeRecordIfCurrent(value storedUserCredential, generation uint64) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.generation[value.UserID] != generation {
		return errors.New("GitHub user credential was invalidated during update")
	}
	if err := p.storeRecord(value); err != nil {
		return err
	}
	p.clearActiveLocked(value.UserID)
	return nil
}

func (p *userProvider) load(userID int64) (storedUserCredential, error) {
	encoded, _, err := p.store.Get(userSlot(userID), userCredentialKind)
	if err != nil {
		return storedUserCredential{}, errors.New("GitHub user credential is unavailable")
	}
	defer zero(encoded)
	var result storedUserCredential
	if err := strictjson.Decode(encoded, &result, true); err != nil || result.UserID != userID {
		zeroStored(&result)
		return storedUserCredential{}, errors.New("GitHub user credential is invalid")
	}
	return result, nil
}

func (p *userProvider) clearActiveLocked(userID int64) {
	if current := p.active[userID]; current != nil {
		current.invalidate()
		delete(p.active, userID)
	}
}

func (p *userProvider) activate(userID int64, generation uint64, credential *Credential) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.generation[userID] != generation {
		return errors.New("GitHub user credential was invalidated while it was loaded")
	}
	p.clearActiveLocked(userID)
	p.active[userID] = credential
	return nil
}

func (p *userProvider) activeCredential(userID int64, expiresAt time.Time) *Credential {
	p.mu.Lock()
	defer p.mu.Unlock()
	credential := p.active[userID]
	if credential == nil || !credential.metadata.ExpiresAt.Equal(expiresAt.UTC()) {
		return nil
	}
	token, err := credential.tokenCopy()
	if err != nil {
		delete(p.active, userID)
		return nil
	}
	zero(token)
	return credential
}

func (p *userProvider) userGeneration(userID int64) uint64 {
	return lockedMapValue(&p.mu, p.generation, userID)
}

func (p *userProvider) lockUser(userID int64) func() {
	value, _ := p.locks.LoadOrStore(userID, &sync.Mutex{})
	lock := value.(*sync.Mutex)
	lock.Lock()
	return lock.Unlock
}

func userSlot(userID int64) string { return "github-user-" + strconv.FormatInt(userID, 10) }

func zeroStored(value *storedUserCredential) {
	if value == nil {
		return
	}
	zero(value.AccessToken)
	zero(value.RefreshToken)
}

// DecodeUserEnrollment decodes a bounded protected-file payload for the local
// setup command. Secret values are retained only in the returned byte slices.
func DecodeUserEnrollment(data []byte) (UserEnrollment, error) {
	if len(data) == 0 || len(data) > maxOAuthBodyBytes {
		return UserEnrollment{}, errors.New("GitHub user enrollment file is invalid")
	}
	var wire struct {
		UserID           int64     `json:"user_id"`
		Login            string    `json:"login"`
		AccessToken      string    `json:"access_token"`
		RefreshToken     string    `json:"refresh_token"`
		AccessExpiresAt  time.Time `json:"access_expires_at"`
		RefreshExpiresAt time.Time `json:"refresh_expires_at"`
	}
	if err := strictjson.Decode(data, &wire, true); err != nil {
		return UserEnrollment{}, errors.New("GitHub user enrollment file is invalid")
	}
	return UserEnrollment{UserID: wire.UserID, Login: wire.Login, AccessToken: []byte(wire.AccessToken), RefreshToken: []byte(wire.RefreshToken),
		AccessExpiresAt: wire.AccessExpiresAt, RefreshExpiresAt: wire.RefreshExpiresAt}, nil
}
