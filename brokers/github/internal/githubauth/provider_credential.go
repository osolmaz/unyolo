package githubauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v88/github"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/providercredential"
)

const appEnrollmentURL = "https://github.com/settings/apps/new"

// ProviderAdapter projects a GitHub App and its installations into the
// provider-neutral credential authority model.
type ProviderAdapter struct {
	AppID      string
	APIBaseURL *url.URL
	HTTPClient *http.Client
	Generation uint64
}

func (ProviderAdapter) Provider() string { return "github" }

func (ProviderAdapter) Enrollment(context.Context) (providercredential.Enrollment, error) {
	return providercredential.Enrollment{URL: appEnrollmentURL, Instructions: "Create and install a GitHub App with only the repositories and permissions this broker may use."}, nil
}

func (a ProviderAdapter) Inspect(ctx context.Context, secret *providercredential.Secret) (providercredential.Snapshot, error) {
	privateKey, err := secret.Bytes()
	if err != nil {
		return providercredential.Snapshot{}, err
	}
	defer clear(privateKey)
	apiURL, err := normalizeAPIURL(a.APIBaseURL)
	if err != nil {
		return providercredential.Snapshot{}, err
	}
	provider, err := newAppProvider(a.AppID, privateKey, apiURL, configuredHTTPClient(a.HTTPClient))
	if err != nil {
		return providercredential.Snapshot{}, err
	}
	return a.inspectProvider(ctx, provider, privateKey)
}

func (a ProviderAdapter) inspectProvider(ctx context.Context, provider *appProvider, privateKey []byte) (providercredential.Snapshot, error) {
	if err := provider.check(ctx); err != nil {
		return providercredential.Snapshot{}, err
	}
	installations, err := provider.installations(ctx)
	if err != nil {
		return providercredential.Snapshot{}, err
	}
	return a.snapshotFromInstallations(privateKey, installations)
}

// CurrentSnapshot revalidates the exact selected authority against GitHub
// before reconstructing its secret-free operation binding.
func (m *Manager) CurrentSnapshot(ctx context.Context, selected Metadata, generation uint64, now time.Time) (providercredential.Snapshot, error) {
	if m == nil {
		return providercredential.Snapshot{}, errors.New("GitHub credential provider is unavailable")
	}
	current, err := m.currentMetadata(ctx, selected)
	if err != nil {
		return providercredential.Snapshot{}, err
	}
	return SnapshotForMetadata(current, generation, now)
}

func (m *Manager) currentMetadata(ctx context.Context, selected Metadata) (Metadata, error) {
	current, err := m.revalidateMetadata(ctx, selected)
	if err != nil {
		return Metadata{}, err
	}
	current.APIHost = m.apiURL.Host
	current.ExpiresAt = time.Time{}
	return current, nil
}

func (m *Manager) revalidateMetadata(ctx context.Context, selected Metadata) (Metadata, error) {
	switch selected.Kind {
	case KindAppJWT:
		return selected, m.CheckApp(ctx)
	case KindInstallation:
		return selected, m.validateInstallationMetadata(ctx, selected)
	case KindUser:
		credential, err := m.UserCredential(ctx, selected.UserID)
		if err != nil {
			return Metadata{}, err
		}
		return credential.Metadata(), nil
	default:
		return Metadata{}, errors.New("GitHub credential kind cannot be revalidated")
	}
}

func (m *Manager) validateInstallationMetadata(ctx context.Context, selected Metadata) error {
	installation, err := m.currentInstallation(ctx, selected.InstallationID)
	if err != nil {
		return err
	}
	if !permissionsCover(installationPermissionMap(installation.GetPermissions()), selected.Permissions) {
		return errors.New("GitHub installation permissions no longer satisfy the selected authority")
	}
	return m.validateRepositorySelection(ctx, selected)
}

func (m *Manager) currentInstallation(ctx context.Context, installationID int64) (*github.Installation, error) {
	if m.app == nil || installationID <= 0 {
		return nil, errors.New("GitHub App installation is unavailable")
	}
	return m.app.installationByID(ctx, installationID, false)
}

func (m *Manager) validateRepositorySelection(ctx context.Context, selected Metadata) error {
	repositoryIDs := canonicalRepositoryIDs(selected.RepositoryIDs)
	if len(repositoryIDs) != len(selected.RepositoryIDs) {
		return errors.New("GitHub repository selection is invalid")
	}
	for _, repositoryID := range repositoryIDs {
		repositoryInstallation, repositoryErr := m.app.installationByID(ctx, repositoryID, true)
		if repositoryErr != nil {
			return repositoryErr
		}
		if repositoryInstallation.GetID() != selected.InstallationID {
			return errors.New("GitHub repository is no longer available to the selected installation")
		}
	}
	return nil
}

func permissionsCover(current, required map[string]string) bool {
	for name, requiredAccess := range required {
		currentAccess := githubAccess(current[name])
		requiredLevel := githubAccess(requiredAccess)
		if currentAccess == providercredential.AccessNone || requiredLevel == providercredential.AccessNone ||
			requiredLevel == providercredential.AccessWrite && currentAccess != providercredential.AccessWrite {
			return false
		}
	}
	return true
}

func (a ProviderAdapter) snapshotFromInstallations(privateKey []byte, installations []*github.Installation) (providercredential.Snapshot, error) {
	generation := a.Generation
	if generation == 0 {
		generation = 1
	}
	digest := sha256.Sum256(privateKey)
	capabilities := []providercredential.Capability{{Domain: "github", Permission: "credential.app-jwt", AccessLevel: providercredential.AccessRead}}
	for _, installation := range installations {
		resource := providercredential.ResourceSelector{Kind: "installation", Name: strconv.FormatInt(installation.GetID(), 10)}
		capabilities = append(capabilities, providercredential.Capability{Domain: "github", Permission: "credential.installation", AccessLevel: providercredential.AccessRead, Resource: resource})
		permissions, permissionErr := normalizedInstallationPermissions(installation.GetPermissions())
		if permissionErr != nil {
			return providercredential.Snapshot{}, permissionErr
		}
		for name, access := range permissions {
			capabilities = append(capabilities, providercredential.Capability{Domain: "github", Permission: name, AccessLevel: githubAccess(access), Resource: resource})
		}
	}
	return providercredential.Normalize(providercredential.Snapshot{ // #nosec G101 -- secret-free credential metadata.
		Provider: "github", CredentialKind: "github_app", Subject: strings.TrimSpace(a.AppID), FingerprintSHA256: hex.EncodeToString(digest[:]),
		Generation: generation, VerifiedAt: time.Now().UTC(), VerificationState: providercredential.VerificationValid, Capabilities: capabilities,
	})
}

func (ProviderAdapter) Requirement(operation string) (providercredential.Requirement, bool) {
	descriptor, found := opcatalog.ByName(operation)
	if !found {
		return providercredential.Requirement{}, false
	}
	clauses := make([]providercredential.AnyOf, 0, len(descriptor.RequiredGitHubPermissions)+1)
	switch descriptor.CredentialKind {
	case string(KindAppJWT):
		clauses = append(clauses, providercredential.AnyOf{Alternatives: []providercredential.Need{{Domain: "github", Permission: "credential.app-jwt", MinimumAccessLevel: providercredential.AccessRead}}})
	case string(KindInstallation):
		clauses = append(clauses, providercredential.AnyOf{Alternatives: []providercredential.Need{{Domain: "github", Permission: "credential.installation", MinimumAccessLevel: providercredential.AccessRead}}})
	case string(KindUser):
		clauses = append(clauses, providercredential.AnyOf{Alternatives: []providercredential.Need{{Domain: "github", Permission: "credential.user", MinimumAccessLevel: providercredential.AccessRead}}})
		// GitHub does not expose a trustworthy permission inventory for user
		// access tokens. The authenticated user is verified here; GitHub remains
		// authoritative for operation-specific token access at execution time.
		return providercredential.Requirement{AllOf: clauses}, true
	default:
		return providercredential.Requirement{}, false
	}
	permissions := make([]string, 0, len(descriptor.RequiredGitHubPermissions))
	for permission := range descriptor.RequiredGitHubPermissions {
		permissions = append(permissions, permission)
	}
	slices.Sort(permissions)
	for _, permission := range permissions {
		access := descriptor.RequiredGitHubPermissions[permission]
		clauses = append(clauses, providercredential.AnyOf{Alternatives: []providercredential.Need{{Domain: "github", Permission: permission, MinimumAccessLevel: githubAccess(access)}}})
	}
	return providercredential.Requirement{AllOf: clauses}, true
}

func (ProviderAdapter) Probe(_ context.Context, snapshot providercredential.Snapshot) (providercredential.ProbeResult, error) {
	if snapshot.VerificationState != providercredential.VerificationValid {
		return providercredential.ProbeResult{State: providercredential.ProbeInvalid}, errors.New("GitHub App credential is not valid")
	}
	return providercredential.ProbeResult{State: providercredential.ProbeValid}, nil
}

func normalizedInstallationPermissions(value any) (map[string]string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("encode GitHub installation permissions")
	}
	permissions := map[string]string{}
	if err := json.Unmarshal(encoded, &permissions); err != nil {
		return nil, errors.New("decode GitHub installation permissions")
	}
	return permissions, nil
}

func githubAccess(value string) providercredential.AccessLevel {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "write", "admin":
		return providercredential.AccessWrite
	case "read":
		return providercredential.AccessRead
	default:
		return providercredential.AccessNone
	}
}

// SnapshotForMetadata creates the exact secret-free authority selected for an
// immutable operation plan.
func SnapshotForMetadata(metadata Metadata, generation uint64, now time.Time) (providercredential.Snapshot, error) {
	if generation == 0 || metadata.Kind == "" {
		return providercredential.Snapshot{}, errors.New("GitHub credential metadata is invalid")
	}
	identity := fmt.Sprintf("%s:%d:%d", metadata.Kind, metadata.InstallationID, metadata.UserID)
	fingerprint := sha256.Sum256([]byte(identity + ":" + metadata.APIHost))
	capabilities := make([]providercredential.Capability, 0, len(metadata.Permissions)+1)
	capabilities = append(capabilities, providercredential.Capability{Domain: "github", Permission: "credential." + string(metadata.Kind), AccessLevel: providercredential.AccessRead})
	if metadata.InstallationID > 0 {
		capabilities = append(capabilities, providercredential.Capability{Domain: "github", Permission: "selection.installation", AccessLevel: providercredential.AccessRead,
			Resource: providercredential.ResourceSelector{Kind: "installation", Name: strconv.FormatInt(metadata.InstallationID, 10)}})
	}
	for _, repositoryID := range metadata.RepositoryIDs {
		capabilities = append(capabilities, providercredential.Capability{Domain: "github", Permission: "selection.repository", AccessLevel: providercredential.AccessRead,
			Resource: providercredential.ResourceSelector{Kind: "repository", Name: strconv.FormatInt(repositoryID, 10)}})
	}
	for permission, access := range metadata.Permissions {
		capabilities = append(capabilities, providercredential.Capability{Domain: "github", Permission: permission, AccessLevel: githubAccess(access)})
	}
	return providercredential.Normalize(providercredential.Snapshot{Provider: "github", CredentialKind: string(metadata.Kind), Subject: identity,
		FingerprintSHA256: hex.EncodeToString(fingerprint[:]), Generation: generation, VerifiedAt: now.UTC(),
		VerificationState: providercredential.VerificationValid, Capabilities: capabilities})
}

var _ providercredential.Adapter = ProviderAdapter{}
