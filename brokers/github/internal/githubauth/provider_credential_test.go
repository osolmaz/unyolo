package githubauth

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/credential/provider"
)

func TestProviderRequirementsCoverCatalogWithoutDevelopmentTokens(t *testing.T) {
	adapter := ProviderAdapter{}
	for _, descriptor := range opcatalog.MustAll() {
		_, found := adapter.Requirement(descriptor.Name)
		want := descriptor.CredentialKind != string(KindDevelopmentToken)
		if found != want {
			t.Fatalf("Requirement(%q) found = %v, want %v", descriptor.Name, found, want)
		}
	}
}

func TestUserCredentialRequirementUsesVerifiableIdentity(t *testing.T) {
	adapter := ProviderAdapter{}
	for _, descriptor := range opcatalog.MustAll() {
		if descriptor.CredentialKind != string(KindUser) || len(descriptor.RequiredGitHubPermissions) == 0 {
			continue
		}
		requirement, found := adapter.Requirement(descriptor.Name)
		if !found || len(requirement.AllOf) != 1 || requirement.AllOf[0].Alternatives[0].Permission != "credential.user" {
			t.Fatalf("user requirement for %q = %+v, found=%v", descriptor.Name, requirement, found)
		}
		snapshot, err := SnapshotForMetadata(Metadata{Kind: KindUser, UserID: 7, APIHost: "api.github.com"}, 1, time.Now())
		if err != nil || !providercredential.Evaluate(snapshot, requirement, providercredential.Target{}).Allowed {
			t.Fatalf("user snapshot did not satisfy %q: %+v, %v", descriptor.Name, snapshot, err)
		}
		return
	}
	t.Fatal("catalog has no user operation with provider permissions")
}

func TestSnapshotForMetadataUsesExactPermissionCeiling(t *testing.T) {
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	snapshot, err := SnapshotForMetadata(Metadata{Kind: KindInstallation, InstallationID: 42, APIHost: "api.github.com",
		Permissions: map[string]string{"contents": "read", "issues": "write"}}, 3, now)
	if err != nil {
		t.Fatal(err)
	}
	requirement := providercredential.Requirement{AllOf: []providercredential.AnyOf{{Alternatives: []providercredential.Need{{Domain: "github", Permission: "contents", MinimumAccessLevel: providercredential.AccessRead}}}}}
	if !providercredential.EvaluateAt(snapshot, requirement, nil, now).Allowed {
		t.Fatal("selected installation permission was not projected")
	}
	requirement.AllOf[0].Alternatives[0].MinimumAccessLevel = providercredential.AccessWrite
	if providercredential.EvaluateAt(snapshot, requirement, nil, now).Allowed {
		t.Fatal("read permission satisfied a write requirement")
	}
}

func TestProviderAdapterInspectsAppAndInstallations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/app":
			assertAppJWT(t, request)
			_, _ = io.WriteString(writer, `{"id":12345,"slug":"broker"}`)
		case "/app/installations":
			assertAppJWT(t, request)
			_, _ = io.WriteString(writer, `[{"id":42,"account":{"login":"acme"},"permissions":{"contents":"read","issues":"write"}}]`)
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)
	base, _ := url.Parse(server.URL)
	secret, err := providercredential.NewSecret(testPrivateKey(t))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Clear()
	snapshot, err := (ProviderAdapter{AppID: "12345", APIBaseURL: base, HTTPClient: server.Client(), Generation: 4}).Inspect(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Generation != 4 || snapshot.Subject != "12345" || !providercredential.CanSatisfy(snapshot,
		providercredential.Requirement{AllOf: []providercredential.AnyOf{{Alternatives: []providercredential.Need{{Domain: "github", Permission: "issues", MinimumAccessLevel: providercredential.AccessWrite}}}}}, time.Now()) {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}

func TestCurrentSnapshotRevalidatesInstallationAuthority(t *testing.T) {
	permissions := "{\"contents\":\"read\"}"
	repositoryInstallationID := int64(42)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/app":
			_, _ = io.WriteString(writer, `{"id":12345,"slug":"broker"}`)
		case "/app/installations/42":
			_, _ = io.WriteString(writer, "{\"id\":42,\"account\":{\"login\":\"acme\"},\"permissions\":"+permissions+"}")
		case "/repositories/99/installation":
			_, _ = io.WriteString(writer, fmt.Sprintf("{\"id\":%d,\"account\":{\"login\":\"acme\"},\"permissions\":%s}", repositoryInstallationID, permissions))
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)
	base, _ := url.Parse(server.URL)
	manager, err := New(Config{AppID: "12345", AppPrivateKey: testPrivateKey(t), APIBaseURL: base, WebBaseURL: base, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	selected := Metadata{Kind: KindInstallation, InstallationID: 42, RepositoryIDs: []int64{99},
		Permissions: map[string]string{"contents": "read"}, APIHost: base.Host}
	snapshot, err := manager.CurrentSnapshot(t.Context(), selected, 7, time.Now())
	if err != nil || snapshot.Generation != 7 {
		t.Fatalf("current snapshot = %+v, %v", snapshot, err)
	}
	if appSnapshot, appErr := manager.CurrentSnapshot(t.Context(), Metadata{Kind: KindAppJWT}, 8, time.Now()); appErr != nil || appSnapshot.CredentialKind != string(KindAppJWT) {
		t.Fatalf("current app snapshot = %+v, %v", appSnapshot, appErr)
	}
	if _, err := manager.CurrentSnapshot(t.Context(), Metadata{Kind: KindDevelopmentToken}, 8, time.Now()); err == nil {
		t.Fatal("non-revalidatable credential kind was accepted")
	}
	invalid := selected
	invalid.RepositoryIDs = []int64{99, 99}
	if _, err := manager.CurrentSnapshot(t.Context(), invalid, 7, time.Now()); err == nil {
		t.Fatal("duplicate repository selection was accepted")
	}
	invalid = selected
	invalid.InstallationID = 0
	if _, err := manager.CurrentSnapshot(t.Context(), invalid, 7, time.Now()); err == nil {
		t.Fatal("missing installation was accepted")
	}
	selected.Permissions["contents"] = "write"
	if _, err := manager.CurrentSnapshot(t.Context(), selected, 7, time.Now()); err == nil {
		t.Fatal("reduced installation permission was accepted")
	}
	selected.Permissions["contents"] = "read"
	repositoryInstallationID = 43
	if _, err := manager.CurrentSnapshot(t.Context(), selected, 7, time.Now()); err == nil {
		t.Fatal("repository reassigned to another installation was accepted")
	}
}

func TestProviderAdapterContractMetadata(t *testing.T) {
	adapter := ProviderAdapter{}
	if adapter.Provider() != "github" {
		t.Fatal("unexpected provider")
	}
	enrollment, err := adapter.Enrollment(t.Context())
	if err != nil || enrollment.URL != appEnrollmentURL || enrollment.Instructions == "" {
		t.Fatalf("enrollment = %+v, %v", enrollment, err)
	}
	valid := providercredential.Snapshot{VerificationState: providercredential.VerificationValid}
	if probe, err := adapter.Probe(t.Context(), valid); err != nil || probe.State != providercredential.ProbeValid {
		t.Fatalf("valid probe = %+v, %v", probe, err)
	}
	valid.VerificationState = providercredential.VerificationUnavailable
	if probe, err := adapter.Probe(t.Context(), valid); err == nil || probe.State != providercredential.ProbeInvalid {
		t.Fatalf("invalid probe = %+v, %v", probe, err)
	}
	if githubAccess("admin") != providercredential.AccessWrite || githubAccess("unknown") != providercredential.AccessNone {
		t.Fatal("GitHub access normalization failed")
	}
}

func TestProviderAdapterRejectsUnverifiableAppAuthority(t *testing.T) {
	for _, test := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{name: "app rejected", handler: func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusUnauthorized) }},
		{name: "installations invalid", handler: func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/app" {
				_, _ = io.WriteString(writer, `{"id":12345,"slug":"broker"}`)
				return
			}
			_, _ = io.WriteString(writer, `{`)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()
			base, _ := url.Parse(server.URL)
			secret, err := providercredential.NewSecret(testPrivateKey(t))
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Clear()
			if _, err := (ProviderAdapter{AppID: "12345", APIBaseURL: base, HTTPClient: server.Client()}).Inspect(t.Context(), secret); err == nil {
				t.Fatal("unverifiable GitHub App authority was accepted")
			}
		})
	}
}
