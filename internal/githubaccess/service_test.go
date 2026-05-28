package githubaccess

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestConfigureAcceptsOwnersAndRepositories(t *testing.T) {
	t.Parallel()
	service := NewService(NewMemoryStore())
	service.now = func() time.Time {
		return time.Date(2026, 5, 28, 1, 2, 3, 0, time.UTC)
	}
	service.newID = func() (string, error) {
		return "gha_test", nil
	}
	selection, err := service.Configure(context.Background(), ConfigureInput{
		CredentialID: " cred_123 ",
		Owners:       []string{" dutifuldev ", "dutifuldev", "osolmaz"},
		Repositories: []RepositoryRef{
			{Owner: "openclaw", Name: "openclaw"},
			{Owner: "openclaw", Name: "openclaw"},
		},
	})
	if err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	if selection.ID != "gha_test" || selection.CredentialID != "cred_123" {
		t.Fatalf("Configure() = %+v, want normalized selection", selection)
	}
	if len(selection.Owners) != 2 || len(selection.Repositories) != 1 {
		t.Fatalf("Configure() = %+v, want deduplicated owners and repos", selection)
	}
	got, err := service.Get(context.Background(), " gha_test ")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.ID != selection.ID {
		t.Fatalf("Get().ID = %q, want %q", got.ID, selection.ID)
	}
	list, err := service.List(context.Background())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("List() length = %d, want 1", len(list))
	}
}

func TestConfigureRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	cases := []ConfigureInput{
		{Owners: []string{"dutifuldev"}},
		{CredentialID: "cred_123"},
		{CredentialID: "cred_123", Owners: []string{"bad/owner"}},
		{CredentialID: "cred_123", Repositories: []RepositoryRef{{Owner: "bad/owner", Name: "repo"}}},
		{CredentialID: "cred_123", Repositories: []RepositoryRef{{Owner: "owner", Name: "bad/repo"}}},
	}
	service := NewService(NewMemoryStore())
	for _, input := range cases {
		if _, err := service.Configure(context.Background(), input); err == nil {
			t.Fatalf("Configure(%+v) error = nil, want validation error", input)
		}
	}
}

func TestGetNotFound(t *testing.T) {
	t.Parallel()
	service := NewService(NewMemoryStore())
	_, err := service.Get(context.Background(), "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() error = %v, want ErrNotFound", err)
	}
}

func TestMemoryStoreRejectsDuplicateID(t *testing.T) {
	t.Parallel()
	store := NewMemoryStore()
	selection := Selection{ID: "gha_test", CredentialID: "cred_123", Owners: []string{"dutifuldev"}}
	if _, err := store.Create(context.Background(), selection); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := store.Create(context.Background(), selection); err == nil {
		t.Fatal("Create() duplicate error = nil")
	}
}
