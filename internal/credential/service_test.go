package credential

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRegisterDoesNotExposeSecretMaterial(t *testing.T) {
	t.Parallel()
	service := NewService(NewDiscardingSecretSink(), NewMemoryMetadataStore())
	rawSecret := "private-" + "repo-" + "read-" + "value"
	secret, err := NewSecretMaterial(rawSecret)
	if err != nil {
		t.Fatalf("NewSecretMaterial() error = %v", err)
	}
	record, err := service.Register(context.Background(), RegisterInput{
		Name:   "github-read",
		Kind:   KindGitHubToken,
		Secret: secret,
		Scopes: []string{"contents:read", "contents:read"},
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	body, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if strings.Contains(string(body), rawSecret) {
		t.Fatalf("public metadata exposed original credential: %s", body)
	}
	if len(record.Scopes) != 1 {
		t.Fatalf("Scopes length = %d, want 1", len(record.Scopes))
	}
}

func TestRegisterRejectsUnsupportedKind(t *testing.T) {
	t.Parallel()
	service := NewService(NewDiscardingSecretSink(), NewMemoryMetadataStore())
	secret, err := NewSecretMaterial("secret")
	if err != nil {
		t.Fatalf("NewSecretMaterial() error = %v", err)
	}
	_, err = service.Register(context.Background(), RegisterInput{
		Name:   "github-read",
		Kind:   Kind("ssh_key"),
		Secret: secret,
	})
	if err == nil {
		t.Fatal("Register() error = nil, want unsupported kind error")
	}
}

func TestRegisterRejectsMissingFields(t *testing.T) {
	t.Parallel()
	service := NewService(NewDiscardingSecretSink(), NewMemoryMetadataStore())
	secret, err := NewSecretMaterial("value")
	if err != nil {
		t.Fatalf("NewSecretMaterial() error = %v", err)
	}
	_, err = service.Register(context.Background(), RegisterInput{
		Name:   "",
		Kind:   KindGitHubToken,
		Secret: secret,
	})
	if err == nil {
		t.Fatal("Register() error = nil, want missing name error")
	}
}

func TestGetAndListReturnPublicMetadata(t *testing.T) {
	t.Parallel()
	service := NewService(NewDiscardingSecretSink(), NewMemoryMetadataStore())
	service.now = func() time.Time {
		return time.Date(2026, 5, 28, 1, 2, 3, 0, time.UTC)
	}
	service.newID = func() (string, error) {
		return "cred_test", nil
	}
	secret, err := NewSecretMaterial("value")
	if err != nil {
		t.Fatalf("NewSecretMaterial() error = %v", err)
	}
	created, err := service.Register(context.Background(), RegisterInput{
		Name:   "github-read",
		Kind:   KindGitHubToken,
		Secret: secret,
		Scopes: []string{"contents:read"},
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	got, err := service.Get(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.ID != "cred_test" || got.CreatedAt.IsZero() {
		t.Fatalf("Get() = %+v, want registered public metadata", got)
	}
	list, err := service.List(context.Background())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("List() length = %d, want 1", len(list))
	}
}

func TestGetNotFound(t *testing.T) {
	t.Parallel()
	service := NewService(NewDiscardingSecretSink(), NewMemoryMetadataStore())
	_, err := service.Get(context.Background(), "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get() error = %v, want ErrNotFound", err)
	}
}

func TestDiscardingSecretSinkRejectsEmptySecret(t *testing.T) {
	t.Parallel()
	_, err := NewDiscardingSecretSink().Store(context.Background(), SecretMaterial{})
	if err == nil {
		t.Fatal("Store() error = nil, want empty secret error")
	}
}

func TestMemoryMetadataStoreRejectsDuplicateID(t *testing.T) {
	t.Parallel()
	store := NewMemoryMetadataStore()
	metadata := Metadata{ID: "cred_test", Kind: KindGitHubToken}
	if _, err := store.Create(context.Background(), metadata); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := store.Create(context.Background(), metadata); err == nil {
		t.Fatal("Create() duplicate error = nil")
	}
}

func TestSecretMaterialZero(t *testing.T) {
	t.Parallel()
	secret, err := NewSecretMaterial("do-not-keep")
	if err != nil {
		t.Fatalf("NewSecretMaterial() error = %v", err)
	}
	secret.Zero()
	for _, value := range secret.CloneBytes() {
		if value != 0 {
			t.Fatalf("secret byte = %d, want 0 after Zero", value)
		}
	}
}

func TestNewSecretMaterialRejectsEmptyValue(t *testing.T) {
	t.Parallel()
	if _, err := NewSecretMaterial(""); err == nil {
		t.Fatal("NewSecretMaterial() error = nil, want empty secret error")
	}
}
