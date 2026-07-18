package githubauth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/providercredential"
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
