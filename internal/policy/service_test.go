package policy

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestConfigureRepositoryNormalizesPolicy(t *testing.T) {
	t.Parallel()
	service := NewService(NewMemoryRepositoryStore())
	service.now = func() time.Time {
		return time.Date(2026, 5, 28, 1, 2, 3, 0, time.UTC)
	}
	service.newID = func() (string, error) {
		return "repo_test", nil
	}
	repository, err := service.Configure(context.Background(), RepositoryInput{
		TenantID:     "tenant-a",
		Owner:        "dutifuldev",
		Name:         "gitcba",
		Private:      true,
		CredentialID: "cred_123",
		Policy: RepositoryPolicy{
			AllowedAgents:     []string{"openclaw", "openclaw", " codex "},
			AllowedOperations: []Operation{OperationContentsRead, OperationContentsRead},
			AllowedPaths:      []string{"README.md", "README.md"},
		},
	})
	if err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	if repository.ID != "repo_test" || !repository.Private {
		t.Fatalf("Configure() = %+v, want configured repository", repository)
	}
	if len(repository.Policy.AllowedAgents) != 2 {
		t.Fatalf("AllowedAgents length = %d, want 2", len(repository.Policy.AllowedAgents))
	}
	if len(repository.Policy.AllowedOperations) != 1 {
		t.Fatalf("AllowedOperations length = %d, want 1", len(repository.Policy.AllowedOperations))
	}
	got, err := service.Get(context.Background(), " tenant-a ", " repo_test ")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.Name != "gitcba" {
		t.Fatalf("Get().Name = %q, want gitcba", got.Name)
	}
	list, err := service.List(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("List() length = %d, want 1", len(list))
	}
}

func TestConfigureAcceptsApprovedWritePolicy(t *testing.T) {
	t.Parallel()
	service := NewService(NewMemoryRepositoryStore())
	_, err := service.Configure(context.Background(), RepositoryInput{
		TenantID:     "tenant-a",
		Owner:        "dutifuldev",
		Name:         "gitcba",
		CredentialID: "cred_123",
		Policy: RepositoryPolicy{
			AllowedAgents:            []string{"openclaw"},
			AllowedOperations:        []Operation{OperationContentsWrite},
			AllowedBranches:          []string{"main"},
			AllowedPaths:             []string{"README.md"},
			RequireApprovalForWrites: true,
		},
	})
	if err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
}

func TestConfigureRejectsWritePolicyWithoutApproval(t *testing.T) {
	t.Parallel()
	service := NewService(NewMemoryRepositoryStore())
	_, err := service.Configure(context.Background(), RepositoryInput{
		TenantID:     "tenant-a",
		Owner:        "dutifuldev",
		Name:         "gitcba",
		CredentialID: "cred_123",
		Policy: RepositoryPolicy{
			AllowedAgents:     []string{"openclaw"},
			AllowedOperations: []Operation{OperationContentsWrite},
			AllowedBranches:   []string{"main"},
			AllowedPaths:      []string{"README.md"},
		},
	})
	if err == nil {
		t.Fatal("Configure() error = nil, want approval requirement error")
	}
}

func TestConfigureRejectsWritePolicyWithoutBranches(t *testing.T) {
	t.Parallel()
	service := NewService(NewMemoryRepositoryStore())
	_, err := service.Configure(context.Background(), RepositoryInput{
		TenantID:     "tenant-a",
		Owner:        "dutifuldev",
		Name:         "gitcba",
		CredentialID: "cred_123",
		Policy: RepositoryPolicy{
			AllowedAgents:            []string{"openclaw"},
			AllowedOperations:        []Operation{OperationBranchCreate},
			RequireApprovalForWrites: true,
		},
	})
	if err == nil {
		t.Fatal("Configure() error = nil, want branch allowlist error")
	}
}

func TestConfigureRejectsContentPolicyWithoutPathAllowlist(t *testing.T) {
	t.Parallel()
	service := NewService(NewMemoryRepositoryStore())
	_, err := service.Configure(context.Background(), RepositoryInput{
		TenantID:     "tenant-a",
		Owner:        "dutifuldev",
		Name:         "gitcba",
		CredentialID: "cred_123",
		Policy: RepositoryPolicy{
			AllowedAgents:     []string{"openclaw"},
			AllowedOperations: []Operation{OperationContentsRead},
		},
	})
	if err == nil {
		t.Fatal("Configure() error = nil, want path allowlist error")
	}
}

func TestConfigureRejectsInvalidPolicyAndRepoFields(t *testing.T) {
	t.Parallel()
	validPolicy := RepositoryPolicy{
		AllowedAgents:     []string{"openclaw"},
		AllowedOperations: []Operation{OperationRepoMetadata},
	}
	cases := []RepositoryInput{
		{Owner: "dutifuldev", Name: "gitcba", CredentialID: "cred_123", Policy: validPolicy},
		{TenantID: "tenant-a", Owner: "dutifuldev/gitcba", Name: "gitcba", CredentialID: "cred_123", Policy: validPolicy},
		{TenantID: "tenant-a", Owner: "dutifuldev", Name: "", CredentialID: "cred_123", Policy: validPolicy},
		{TenantID: "tenant-a", Owner: "dutifuldev", Name: "gitcba", Policy: validPolicy},
		{
			TenantID:     "tenant-a",
			Owner:        "dutifuldev",
			Name:         "gitcba",
			CredentialID: "cred_123",
			Policy: RepositoryPolicy{
				AllowedOperations: []Operation{OperationRepoMetadata},
			},
		},
		{
			TenantID:     "tenant-a",
			Owner:        "dutifuldev",
			Name:         "gitcba",
			CredentialID: "cred_123",
			Policy: RepositoryPolicy{
				AllowedAgents: []string{"openclaw"},
			},
		},
		{
			TenantID:     "tenant-a",
			Owner:        "dutifuldev",
			Name:         "gitcba",
			CredentialID: "cred_123",
			Policy: RepositoryPolicy{
				AllowedAgents:     []string{"openclaw"},
				AllowedOperations: []Operation{"delete_repo"},
			},
		},
	}
	service := NewService(NewMemoryRepositoryStore())
	for _, input := range cases {
		if _, err := service.Configure(context.Background(), input); err == nil {
			t.Fatalf("Configure(%+v) error = nil, want validation error", input)
		}
	}
}

func TestRepositoryGetNotFound(t *testing.T) {
	t.Parallel()
	service := NewService(NewMemoryRepositoryStore())
	_, err := service.Get(context.Background(), "tenant-a", "repo_missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() error = %v, want ErrNotFound", err)
	}
}

func TestMemoryRepositoryStoreRejectsDuplicateID(t *testing.T) {
	t.Parallel()
	store := NewMemoryRepositoryStore()
	repository := Repository{ID: "repo_test", TenantID: "tenant-a"}
	if _, err := store.Create(context.Background(), repository); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := store.Create(context.Background(), repository); err == nil {
		t.Fatal("Create() duplicate error = nil")
	}
}
