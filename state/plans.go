package state

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/plandigest"
	"github.com/osolmaz/brokerkit/state/internal/dbsql"
)

type PlanRecord struct {
	Digest     string
	SchemaName string
	Canonical  []byte
	CreatedAt  time.Time
}

func (d *Database) PutPlan(ctx context.Context, schemaName string, canonical []byte, createdAt time.Time) (string, error) {
	if strings.TrimSpace(schemaName) == "" || len(schemaName) > 128 || len(canonical) == 0 || len(canonical) > 1<<20 ||
		!bytes.Equal(bytes.TrimSpace(canonical), canonical) {
		return "", errors.New("canonical plan and schema are required")
	}
	digest := plandigest.Digest(canonical)
	if err := d.queries.PutPlan(ctx, dbsql.PutPlanParams{Digest: digest, SchemaName: schemaName, Canonical: canonical, CreatedAt: formatTime(createdAt)}); err != nil {
		return "", err
	}
	record, err := d.Plan(ctx, digest)
	if err != nil {
		return "", err
	}
	if record.SchemaName != schemaName || !bytes.Equal(record.Canonical, canonical) {
		return "", errors.New("plan digest collision")
	}
	return digest, nil
}

func (d *Database) Plan(ctx context.Context, digest string) (PlanRecord, error) {
	if !plandigest.Valid(digest) {
		return PlanRecord{}, errors.New("plan digest is invalid")
	}
	record, err := d.queries.GetPlan(ctx, digest)
	if err != nil {
		return PlanRecord{}, err
	}
	createdAt, err := parseTime(record.CreatedAt)
	if err != nil {
		return PlanRecord{}, fmt.Errorf("parse plan creation time: %w", err)
	}
	if plandigest.Digest(record.Canonical) != digest {
		return PlanRecord{}, errors.New("plan content digest mismatch")
	}
	return PlanRecord{Digest: record.Digest, SchemaName: record.SchemaName, Canonical: append([]byte(nil), record.Canonical...), CreatedAt: createdAt}, nil
}
