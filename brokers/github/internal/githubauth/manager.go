package githubauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/credential/lifecycle"
	"github.com/osolmaz/brokerkit/credential/store"
)

type Config struct {
	AppID                string
	AppPrivateKey        []byte
	AppClientID          string
	AppClientSecret      []byte
	DevelopmentToken     []byte
	DevelopmentTokenFile string
	APIBaseURL           *url.URL
	WebBaseURL           *url.URL
	HTTPClient           *http.Client
	StreamTimeout        time.Duration
	Store                *credentialstore.Store
	Now                  func() time.Time
	RefreshBefore        time.Duration
	Lifecycle            *credentiallifecycle.Reporter
}

type Manager struct {
	apiURL        *url.URL
	webURL        *url.URL
	client        *http.Client
	streamTimeout time.Duration
	app           *appProvider
	installation  *installationProvider
	user          *userProvider
	development   *Credential
	lifecycle     *credentiallifecycle.Reporter
}

func New(cfg Config) (*Manager, error) {
	cfg.DevelopmentToken = bytes.TrimSpace(cfg.DevelopmentToken)
	apiURL, err := normalizeAPIURL(cfg.APIBaseURL)
	if err != nil {
		return nil, err
	}
	webURL, err := normalizeWebURL(cfg.WebBaseURL)
	if err != nil {
		return nil, err
	}
	client := configuredHTTPClient(cfg.HTTPClient)
	manager := &Manager{apiURL: apiURL, webURL: webURL, client: client, streamTimeout: defaultStreamTimeout(cfg.StreamTimeout), lifecycle: cfg.Lifecycle}
	mode, err := configuredCredentialMode(cfg)
	if err != nil {
		return nil, err
	}
	return manager.configureCredentialProviders(cfg, mode)
}

func configuredHTTPClient(client *http.Client) *http.Client {
	if client != nil {
		return client
	}
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: stopRedirect}
}

func (m *Manager) configureCredentialProviders(cfg Config, mode Kind) (*Manager, error) {
	switch mode {
	case KindUser:
		m.user = m.newUserProvider(cfg)
		return m, nil
	case KindDevelopmentToken:
		m.development = &Credential{metadata: Metadata{Kind: KindDevelopmentToken, APIHost: m.apiURL.Host}, token: append([]byte(nil), cfg.DevelopmentToken...)}
		return m, nil
	default:
		return m.configureAppProviders(cfg)
	}
}

func (m *Manager) configureAppProviders(cfg Config) (*Manager, error) {
	app, err := newAppProvider(cfg.AppID, cfg.AppPrivateKey, m.apiURL, m.client)
	if err != nil {
		return nil, err
	}
	m.app = app
	m.installation = newInstallationProvider(app, m.apiURL, m.client, cfg.Now, cfg.RefreshBefore, cfg.Lifecycle)
	if cfg.Store != nil {
		m.user = m.newUserProvider(cfg)
	}
	return m, nil
}

func defaultStreamTimeout(value time.Duration) time.Duration {
	if value <= 0 {
		return 10 * time.Minute
	}
	return value
}

func configuredCredentialMode(cfg Config) (Kind, error) {
	hasApp, hasDevelopment := hasAppCredential(cfg), len(cfg.DevelopmentToken) > 0
	if hasApp && hasDevelopment {
		return "", errors.New("configure exactly one GitHub App or development credential")
	}
	if hasDevelopment {
		return configuredDevelopmentMode(cfg)
	}
	if hasApp {
		return KindInstallation, nil
	}
	return configuredUserMode(cfg)
}

func hasAppCredential(cfg Config) bool {
	return strings.TrimSpace(cfg.AppID) != "" || len(cfg.AppPrivateKey) > 0
}

func configuredDevelopmentMode(cfg Config) (Kind, error) {
	if strings.TrimSpace(cfg.DevelopmentTokenFile) == "" {
		return "", errors.New("development GitHub token must come from a protected file")
	}
	return KindDevelopmentToken, nil
}

func configuredUserMode(cfg Config) (Kind, error) {
	if cfg.Store == nil || strings.TrimSpace(cfg.AppClientID) == "" || len(cfg.AppClientSecret) == 0 {
		return "", errors.New("GitHub credential provider is not configured")
	}
	return KindUser, nil
}

func (m *Manager) newUserProvider(cfg Config) *userProvider {
	return newUserProvider(cfg.Store, m.apiURL, m.webURL, m.client, cfg.AppClientID, cfg.AppClientSecret, cfg.Now, cfg.RefreshBefore)
}

func (m *Manager) CredentialKind() Kind {
	if m != nil && m.app != nil {
		return KindInstallation
	}
	if m != nil && m.user != nil {
		return KindUser
	}
	return KindDevelopmentToken
}

// SupportsCredentialKind reports whether the runtime can select the reviewed
// credential class for an operation. Development mode deliberately substitutes
// its protected user token for catalog credentials.
func (m *Manager) SupportsCredentialKind(kind Kind, userID int64) bool {
	if m == nil {
		return false
	}
	if m.development != nil {
		return true
	}
	switch kind {
	case KindAppJWT:
		return m.app != nil
	case KindInstallation:
		return m.installation != nil
	case KindUser:
		return m.user != nil && userID > 0 && m.user.store.Exists(userSlot(userID))
	default:
		return false
	}
}

func (m *Manager) CheckApp(ctx context.Context) error {
	if m == nil || m.app == nil {
		return errors.New("GitHub App credential is unavailable")
	}
	return m.app.check(ctx)
}

func (m *Manager) RepositoryCredential(ctx context.Context, operation, owner, repo string) (*Credential, error) {
	if m == nil {
		return nil, errors.New("GitHub credential provider is unavailable")
	}
	if m.development != nil {
		return m.development, nil
	}
	credential, _, err := m.installation.repositoryCredential(ctx, operation, owner, repo)
	return credential, err
}

func (m *Manager) ResolveRepository(ctx context.Context, operation, owner, repo string) (Metadata, error) {
	if m == nil || m.installation == nil {
		return Metadata{}, errors.New("GitHub App credential is unavailable")
	}
	credential, resolution, err := m.installation.repositoryCredential(ctx, operation, owner, repo)
	if err != nil {
		return Metadata{}, err
	}
	metadata := credential.Metadata()
	metadata.RepositoryIDs = []int64{resolution.ID}
	return metadata, nil
}

func (m *Manager) InstallationCredential(ctx context.Context, installationID int64, repositoryIDs []int64, permissions map[string]string) (*Credential, error) {
	return m.installationCredential(ctx, installationID, repositoryIDs, permissions, false)
}

func (m *Manager) installationCredential(ctx context.Context, installationID int64, repositoryIDs []int64, permissions map[string]string, allowEmpty bool) (*Credential, error) {
	if m == nil || m.installation == nil {
		return nil, errors.New("GitHub App credential is unavailable")
	}
	return m.installation.credential(ctx, installationID, repositoryIDs, permissions, allowEmpty)
}

func (m *Manager) InstallationForAccount(ctx context.Context, account string) (Metadata, error) {
	if m == nil || m.app == nil {
		return Metadata{}, errors.New("GitHub App credential is unavailable")
	}
	installation, err := m.app.installationForAccount(ctx, account)
	if err != nil {
		return Metadata{}, err
	}
	return Metadata{Kind: KindInstallation, InstallationID: installation.GetID(), APIHost: m.apiURL.Host}, nil
}

func (m *Manager) InvalidateInstallation(installationID int64, disabled bool) {
	if m != nil && m.installation != nil {
		m.installation.invalidate(installationID, disabled)
	}
}

func (m *Manager) EnableInstallation(installationID int64) {
	if m != nil && m.installation != nil {
		m.installation.enable(installationID)
	}
}

func (m *Manager) UserCredential(ctx context.Context, userID int64) (*Credential, error) {
	if m == nil || m.user == nil {
		return nil, errors.New("GitHub user credential provider is unavailable")
	}
	return m.user.credential(ctx, userID)
}

func (m *Manager) EnrollUser(ctx context.Context, enrollment UserEnrollment) error {
	if m == nil || m.user == nil {
		return errors.New("GitHub user credential provider is unavailable")
	}
	err := m.user.enroll(ctx, enrollment, false)
	return errors.Join(err, m.recordUserLifecycle(credentiallifecycle.ActionCreated, enrollment.UserID, false, err))
}

func (m *Manager) RotateUser(ctx context.Context, enrollment UserEnrollment) error {
	if m == nil || m.user == nil {
		return errors.New("GitHub user credential provider is unavailable")
	}
	err := m.user.enroll(ctx, enrollment, true)
	return errors.Join(err, m.recordUserLifecycle(credentiallifecycle.ActionRotated, enrollment.UserID, true, err))
}

func (m *Manager) RevokeUser(ctx context.Context, userID int64) error {
	if m == nil || m.user == nil {
		return errors.New("GitHub user credential provider is unavailable")
	}
	err := m.user.revoke(ctx, userID)
	return errors.Join(err, m.recordUserLifecycle(credentiallifecycle.ActionRevoked, userID, true, err))
}

func (m *Manager) recordUserLifecycle(action credentiallifecycle.Action, userID int64, hadPrevious bool, operationErr error) error {
	if m == nil || m.lifecycle == nil || userID <= 0 {
		return nil
	}
	id := fmt.Sprintf("github-user:%d", userID)
	event := credentiallifecycle.Event{Class: "github-user-oauth", Action: action, Outcome: credentiallifecycle.OutcomeSucceeded, Provider: "github"}
	if hadPrevious {
		event.PreviousID = id
	}
	if action != credentiallifecycle.ActionRevoked {
		event.CurrentID = id
	}
	if operationErr != nil {
		event.Outcome = credentiallifecycle.OutcomeFailed
	}
	return m.lifecycle.Record(event)
}

func (m *Manager) InvalidateUser(userID int64) error {
	if m == nil || m.user == nil {
		return nil
	}
	return m.user.invalidate(userID)
}

func (m *Manager) API(credential *Credential) (*API, error) {
	if m == nil || credential == nil {
		return nil, errors.New("GitHub API credential is unavailable")
	}
	token, err := credential.tokenCopy()
	if err != nil {
		return nil, err
	}
	defer zero(token)
	sdk, err := newGitHubClient(m.client, m.apiURL, token)
	if err != nil {
		return nil, errors.New("initialize GitHub API client")
	}
	return &API{client: sdk}, nil
}

func (m *Manager) Installations(ctx context.Context) ([]int64, error) {
	if m == nil || m.app == nil {
		return nil, errors.New("GitHub App credential is unavailable")
	}
	items, err := m.app.installations(ctx)
	if err != nil {
		return nil, err
	}
	ids := make([]int64, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.GetID())
	}
	return ids, nil
}

func normalizeWebURL(value *url.URL) (*url.URL, error) {
	if value == nil {
		value, _ = url.Parse("https://github.com/")
	}
	result := *value
	if err := validateWebURL(result); err != nil {
		return nil, err
	}
	result.Path = strings.TrimRight(result.Path, "/") + "/"
	return &result, nil
}

func validateWebURL(result url.URL) error {
	if invalidWebScheme(result) {
		return errors.New("GitHub web URL must use HTTPS")
	}
	if invalidWebURLParts(result) {
		return errors.New("GitHub web URL is invalid")
	}
	return nil
}

func invalidWebScheme(result url.URL) bool {
	return result.Scheme != "https" && (result.Scheme != "http" || !localHostname(result.Hostname()))
}

func invalidWebURLParts(result url.URL) bool {
	return result.Host == "" || result.User != nil || result.RawQuery != "" || result.Fragment != ""
}

func stopRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
