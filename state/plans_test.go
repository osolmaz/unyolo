package state

import (
	"bytes"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/plandigest"
)

func TestPlanRepositoryIsContentAddressed(t *testing.T) {
	database, err := Open(t.Context(), t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	canonical := []byte(`{"schema":"v1","operation":"repo.create"}`)
	createdAt := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	digest, err := database.PutPlan(t.Context(), "provider/v1", canonical, createdAt)
	if err != nil || digest != plandigest.Digest(canonical) {
		t.Fatalf("PutPlan() = %q, %v", digest, err)
	}
	second, err := database.PutPlan(t.Context(), "provider/v1", canonical, createdAt.Add(time.Hour))
	if err != nil || second != digest {
		t.Fatalf("idempotent PutPlan() = %q, %v", second, err)
	}
	record, err := database.Plan(t.Context(), digest)
	if err != nil || record.SchemaName != "provider/v1" || !bytes.Equal(record.Canonical, canonical) || !record.CreatedAt.Equal(createdAt) {
		t.Fatalf("Plan() = %+v, %v", record, err)
	}
	if _, err := database.PutPlan(t.Context(), "other/v1", canonical, createdAt); err == nil {
		t.Fatal("PutPlan() accepted one digest with a different schema")
	}
	if _, err := database.Plan(t.Context(), "invalid"); err == nil {
		t.Fatal("Plan() accepted an invalid digest")
	}
	if _, err := database.PutPlan(t.Context(), "", canonical, createdAt); err == nil {
		t.Fatal("PutPlan() accepted an empty schema")
	}
}
