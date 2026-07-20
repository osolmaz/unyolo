package githubauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	github "github.com/google/go-github/v88/github"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/credential/lifecycle"
	"golang.org/x/sync/singleflight"
)

const (
	defaultRefreshBefore = 2 * time.Minute
	maxCachedCredentials = 256
)

type repositoryResolution struct {
	ID             int64
	InstallationID int64
	Owner          string
	Name           string
	Permissions    map[string]string
}

type cacheEntry struct {
	credential *Credential
	refreshAt  time.Time
}

type installationTokenRequest struct {
	RepositoryIDs []int64           `json:"repository_ids,omitempty"`
	Repositories  []string          `json:"repositories,omitempty"`
	Permissions   map[string]string `json:"permissions"`
}

type installationTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type installationProvider struct {
	app           *appProvider
	apiURL        *url.URL
	client        *http.Client
	now           func() time.Time
	refreshBefore time.Duration
	mu            sync.Mutex
	flight        singleflight.Group
	cache         map[string]cacheEntry
	repositories  map[string]repositoryResolution
	disabled      map[int64]bool
	generation    map[int64]uint64
	lifecycle     *credentiallifecycle.Reporter
}

func newInstallationProvider(app *appProvider, apiURL *url.URL, client *http.Client, now func() time.Time, refreshBefore time.Duration, lifecycle *credentiallifecycle.Reporter) *installationProvider {
	if now == nil {
		now = time.Now
	}
	if refreshBefore <= 0 {
		refreshBefore = defaultRefreshBefore
	}
	return &installationProvider{app: app, apiURL: apiURL, client: client, now: now, refreshBefore: refreshBefore,
		cache: map[string]cacheEntry{}, repositories: map[string]repositoryResolution{}, disabled: map[int64]bool{}, generation: map[int64]uint64{}, lifecycle: lifecycle}
}

func (p *installationProvider) credential(ctx context.Context, installationID int64, repositoryIDs []int64, permissions map[string]string, allowEmpty bool) (*Credential, error) {
	repositoryIDs = canonicalRepositoryIDs(repositoryIDs)
	if installationID <= 0 {
		return nil, errors.New("exact GitHub installation id is required")
	}
	validatedPermissions, err := installationPermissions(permissions, allowEmpty)
	if err != nil {
		return nil, err
	}
	key := credentialCacheKey(installationID, repositoryIDs, permissions, allowEmpty, p.apiURL.Host, p.refreshBefore)
	value, err, _ := p.flight.Do(key, func() (any, error) {
		return p.mintCredential(ctx, key, installationID, repositoryIDs, validatedPermissions, allowEmpty)
	})
	if err != nil {
		return nil, err
	}
	credential, ok := value.(*Credential)
	if !ok {
		return nil, errors.New("GitHub installation credential is unavailable")
	}
	return credential, nil
}

func (p *installationProvider) mintCredential(ctx context.Context, key string, installationID int64, repositoryIDs []int64, permissions map[string]string, allowEmpty bool) (*Credential, error) {
	generation, now, cached, err := p.cachedCredentialState(key, installationID)
	if err != nil || cached != nil {
		return cached, err
	}
	token, err := p.createInstallationToken(ctx, installationID, installationTokenRequest{
		RepositoryIDs: repositoryIDs,
		Permissions:   permissions,
	})
	if err != nil {
		return nil, err
	}
	credential, err := p.credentialFromToken(installationID, repositoryIDs, permissions, allowEmpty, token, now)
	if err != nil {
		return nil, err
	}
	return p.storeMintedCredential(ctx, key, installationID, generation, now, credential)
}

func (p *installationProvider) cachedCredentialState(key string, installationID int64) (uint64, time.Time, *Credential, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.disabled[installationID] {
		return 0, time.Time{}, nil, errors.New("GitHub installation is suspended or deleted")
	}
	generation := p.generation[installationID]
	now := p.now().UTC()
	if entry, ok := p.cache[key]; ok && now.Before(entry.refreshAt) {
		return generation, now, entry.credential, nil
	}
	return generation, now, nil, nil
}

func (p *installationProvider) credentialFromToken(installationID int64, repositoryIDs []int64, permissions map[string]string, allowEmpty bool, token installationTokenResponse, now time.Time) (*Credential, error) {
	value := []byte(strings.TrimSpace(token.Token))
	expiresAt := token.ExpiresAt.UTC()
	if len(value) == 0 || !expiresAt.After(now.Add(p.refreshBefore)) {
		zero(value)
		return nil, errors.New("GitHub installation token response is invalid")
	}
	return &Credential{metadata: Metadata{Kind: KindInstallation, InstallationID: installationID,
		RepositoryIDs: slices.Clone(repositoryIDs), Permissions: clonePermissions(permissions), AllowEmptyPermissions: allowEmpty,
		APIHost: p.apiURL.Host, ExpiresAt: expiresAt}, token: value}, nil
}

func (p *installationProvider) storeMintedCredential(ctx context.Context, key string, installationID int64, generation uint64, now time.Time, credential *Credential) (*Credential, error) {
	p.mu.Lock()
	if p.disabled[installationID] || p.generation[installationID] != generation {
		p.mu.Unlock()
		revokeErr := p.revokeCredential(ctx, credential)
		return nil, errors.Join(errors.New("GitHub installation credential was invalidated while it was issued"), revokeErr)
	}
	p.evictExpired(now)
	if len(p.cache) >= maxCachedCredentials {
		p.evictOldest()
	}
	p.cache[key] = cacheEntry{credential: credential, refreshAt: credential.metadata.ExpiresAt.Add(-p.refreshBefore)}
	p.mu.Unlock()
	return credential, nil
}

func (p *installationProvider) revokeCredential(ctx context.Context, credential *Credential) error {
	installationID := credential.Metadata().InstallationID
	token, err := credential.tokenCopy()
	if err != nil {
		credential.invalidate()
		return errors.Join(err, p.recordRevocation(installationID, err))
	}
	defer zero(token)
	defer credential.invalidate()
	client, err := newGitHubClient(p.client, p.apiURL, token)
	if err != nil {
		return errors.Join(err, p.recordRevocation(installationID, err))
	}
	revokeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, revokeErr := client.Apps.RevokeInstallationToken(revokeCtx)
	classified := classifyAPIError(revokeErr)
	return errors.Join(classified, p.recordRevocation(installationID, classified))
}

func (p *installationProvider) recordRevocation(installationID int64, operationErr error) error {
	if !canReportInstallationLifecycle(p, installationID) {
		return nil
	}
	return p.lifecycle.Record(credentiallifecycle.Event{Class: "github-installation", Action: credentiallifecycle.ActionRevoked,
		Outcome: lifecycleOutcome(operationErr), PreviousID: fmt.Sprintf("github-installation:%d", installationID), Provider: "github"})
}

func canReportInstallationLifecycle(provider *installationProvider, installationID int64) bool {
	return provider != nil && provider.lifecycle != nil && installationID > 0
}

func lifecycleOutcome(err error) credentiallifecycle.Outcome {
	if err != nil {
		return credentiallifecycle.OutcomeFailed
	}
	return credentiallifecycle.OutcomeSucceeded
}

func (p *installationProvider) repositoryCredential(ctx context.Context, operation, owner, repo string) (*Credential, repositoryResolution, error) {
	permissions, err := permissionsForOperation(operation)
	if err != nil {
		return nil, repositoryResolution{}, err
	}
	resolution, err := p.resolveRepository(ctx, owner, repo, permissions)
	if err != nil {
		return nil, repositoryResolution{}, err
	}
	credential, err := p.credential(ctx, resolution.InstallationID, []int64{resolution.ID}, permissions, false)
	return credential, resolution, err
}

func (p *installationProvider) resolveRepository(ctx context.Context, owner, repo string, permissions map[string]string) (repositoryResolution, error) {
	owner, repo, err := normalizedRepositoryName(owner, repo)
	if err != nil {
		return repositoryResolution{}, err
	}
	lookupKey := strings.ToLower(p.apiURL.Host + "\x00" + owner + "\x00" + repo)
	if cached, ok := p.cachedRepository(lookupKey); ok {
		return cached, nil
	}
	installation, err := p.app.repositoryInstallation(ctx, owner, repo)
	if err != nil {
		return repositoryResolution{}, err
	}
	if p.installationDisabled(installation.GetID()) {
		return repositoryResolution{}, errors.New("GitHub installation is suspended or deleted")
	}
	validatedPermissions, err := installationPermissions(permissions, false)
	if err != nil {
		return repositoryResolution{}, err
	}
	result, err := p.resolveRepositoryID(ctx, installation, owner, repo, validatedPermissions)
	if err != nil {
		return repositoryResolution{}, err
	}
	p.cacheRepository(lookupKey, result)
	return result, nil
}

func normalizedRepositoryName(owner, repo string) (string, string, error) {
	owner, repo = strings.TrimSpace(owner), strings.TrimSpace(repo)
	if owner == "" || repo == "" {
		return "", "", errors.New("GitHub repository is required")
	}
	return owner, repo, nil
}

func (p *installationProvider) cachedRepository(key string) (repositoryResolution, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	cached, ok := p.repositories[key]
	return cached, ok && !p.disabled[cached.InstallationID]
}

func (p *installationProvider) cacheRepository(key string, result repositoryResolution) {
	p.mu.Lock()
	if !p.disabled[result.InstallationID] {
		p.repositories[key] = result
	}
	p.mu.Unlock()
}

// GitHub's repository-installation response does not include the repository
// id. Mint one uncached name-restricted credential, resolve the immutable id,
// revoke that bootstrap credential, then mint/cache only by repository id.
func (p *installationProvider) resolveRepositoryID(ctx context.Context, installation *github.Installation, owner, repo string, permissions map[string]string) (repositoryResolution, error) {
	sdk, err := p.bootstrapRepositoryResolver(ctx, installation.GetID(), repo, permissions)
	if err != nil {
		return repositoryResolution{}, err
	}
	resolved, _, getErr := sdk.Repositories.Get(ctx, owner, repo)
	revokeErr := revokeBootstrapCredential(ctx, sdk)
	auditErr := p.recordRevocation(installation.GetID(), revokeErr)
	if getErr != nil {
		return repositoryResolution{}, errors.Join(classifyAPIError(getErr), classifyAPIError(revokeErr), auditErr)
	}
	if retirementErr := bootstrapRetirementError(revokeErr, auditErr); retirementErr != nil {
		return repositoryResolution{}, retirementErr
	}
	if !resolvedRepositoryMatches(resolved, owner, repo) {
		return repositoryResolution{}, errors.New("GitHub repository identity response is invalid")
	}
	return repositoryResolution{ID: resolved.GetID(), InstallationID: installation.GetID(), Owner: resolved.GetOwner().GetLogin(), Name: resolved.GetName(),
		Permissions: installationPermissionMap(installation.GetPermissions())}, nil
}

func (p *installationProvider) bootstrapRepositoryResolver(ctx context.Context, installationID int64, repo string, permissions map[string]string) (*github.Client, error) {
	token, err := p.createInstallationToken(ctx, installationID, installationTokenRequest{
		Repositories: []string{repo},
		Permissions:  permissions,
	})
	if err != nil {
		return nil, err
	}
	bootstrap := []byte(token.Token)
	defer zero(bootstrap)
	if len(bootstrap) == 0 {
		return nil, errors.New("GitHub repository resolution credential is invalid")
	}
	sdk, err := newGitHubClient(p.client, p.apiURL, bootstrap)
	if err != nil {
		return nil, errors.New("initialize GitHub repository resolver")
	}
	return sdk, nil
}

func revokeBootstrapCredential(ctx context.Context, sdk *github.Client) error {
	_, err := sdk.Apps.RevokeInstallationToken(ctx)
	return err
}

func bootstrapRetirementError(revokeErr, auditErr error) error {
	return errors.Join(classifyAPIError(revokeErr), auditErr)
}

func resolvedRepositoryMatches(resolved *github.Repository, owner, repo string) bool {
	return resolved.GetID() > 0 && strings.EqualFold(resolved.GetName(), repo) && strings.EqualFold(resolved.GetOwner().GetLogin(), owner)
}

func (p *installationProvider) invalidate(installationID int64, disabled bool) {
	if p == nil || installationID <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.generation[installationID]++
	for key, entry := range p.cache {
		if entry.credential.metadata.InstallationID == installationID {
			entry.credential.invalidate()
			delete(p.cache, key)
		}
	}
	for key, repository := range p.repositories {
		if repository.InstallationID == installationID {
			delete(p.repositories, key)
		}
	}
	p.disabled[installationID] = disabled
}

func (p *installationProvider) enable(installationID int64) {
	if p == nil || installationID <= 0 {
		return
	}
	p.mu.Lock()
	delete(p.disabled, installationID)
	p.mu.Unlock()
}

func (p *installationProvider) installationDisabled(id int64) bool {
	return lockedMapValue(&p.mu, p.disabled, id)
}

func (p *installationProvider) evictExpired(now time.Time) {
	for key, entry := range p.cache {
		if !now.Before(entry.refreshAt) {
			entry.credential.invalidate()
			delete(p.cache, key)
		}
	}
}

func (p *installationProvider) evictOldest() {
	var oldestKey string
	var oldest time.Time
	for key, entry := range p.cache {
		if oldestKey == "" || entry.refreshAt.Before(oldest) {
			oldestKey, oldest = key, entry.refreshAt
		}
	}
	if oldestKey != "" {
		p.cache[oldestKey].credential.invalidate()
		delete(p.cache, oldestKey)
	}
}

func credentialCacheKey(installationID int64, repositoryIDs []int64, permissions map[string]string, allowEmpty bool, host string, refreshBefore time.Duration) string {
	parts := []string{strconv.FormatInt(installationID, 10), host, refreshBefore.String(), strconv.FormatBool(allowEmpty)}
	for _, id := range canonicalRepositoryIDs(repositoryIDs) {
		parts = append(parts, strconv.FormatInt(id, 10))
	}
	keys := make([]string, 0, len(permissions))
	for key := range permissions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts = append(parts, key+"="+permissions[key])
	}
	return strings.Join(parts, "\x00")
}

func canonicalRepositoryIDs(ids []int64) []int64 {
	result := slices.Clone(ids)
	slices.Sort(result)
	result = slices.Compact(result)
	for _, id := range result {
		if id <= 0 {
			return nil
		}
	}
	return result
}

func (p *installationProvider) createInstallationToken(ctx context.Context, installationID int64, options installationTokenRequest) (installationTokenResponse, error) {
	if p == nil || p.app == nil || p.app.client == nil || installationID <= 0 {
		return installationTokenResponse{}, errors.New("GitHub installation token request is invalid")
	}
	request, err := p.app.client.NewRequest(ctx, http.MethodPost, fmt.Sprintf("app/installations/%d/access_tokens", installationID), options)
	if err != nil {
		return installationTokenResponse{}, errors.New("create GitHub installation token request")
	}
	var token installationTokenResponse
	if _, err := p.app.client.Do(request, &token); err != nil {
		return installationTokenResponse{}, classifyAPIError(err)
	}
	return token, nil
}

func installationPermissions(value map[string]string, allowEmpty bool) (map[string]string, error) {
	if len(value) == 0 && !allowEmpty {
		return nil, errors.New("GitHub installation permission map is invalid")
	}
	result := make(map[string]string, len(value))
	for key, level := range value {
		if !knownInstallationPermission(key) || (level != "read" && level != "write") {
			return nil, errors.New("GitHub installation permission map is invalid")
		}
		result[key] = level
	}
	return result, nil
}

func knownInstallationPermission(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	for _, descriptor := range opcatalog.MustAll() {
		if _, found := descriptor.RequiredGitHubPermissions[name]; found {
			return true
		}
	}
	return false
}

func installationPermissionMap(value *github.InstallationPermissions) map[string]string {
	if value == nil {
		return nil
	}
	encoded, _ := json.Marshal(value)
	var result map[string]string
	_ = json.Unmarshal(encoded, &result)
	return result
}

func permissionsForOperation(operation string) (map[string]string, error) {
	if descriptor, ok := opcatalog.ByName(operation); ok {
		if descriptor.CredentialKind != string(KindInstallation) {
			return nil, fmt.Errorf("GitHub operation %q does not use an installation credential", operation)
		}
		return clonePermissions(descriptor.RequiredGitHubPermissions), nil
	}
	switch {
	case operation == "git.fetch", operation == "git.push.advertise":
		return map[string]string{"contents": "read"}, nil
	case strings.HasPrefix(operation, "git.push."), operation == "git.ref.delete", operation == "git.tag.update":
		return map[string]string{"contents": "write"}, nil
	default:
		return nil, fmt.Errorf("GitHub operation %q has no credential binding", operation)
	}
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
