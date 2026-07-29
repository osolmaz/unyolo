package grants

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/internal/copyx"
)

func (s *Store) prepareLifecycle(data *fileData) bool {
	expired := s.expireDue(data)
	retained := s.retainStaleReservations(data)
	return expired || retained
}

func (s *Store) retainStaleReservations(data *fileData) bool {
	now := s.opts.Now().UTC()
	changedGrants := make(map[string]int)
	for index, use := range data.Uses {
		_, grant, err := findGrant(data.Grants, use.GrantID)
		if err != nil || !useReservationIsStale(use, grant, now, s.opts.ReservationTimeout) {
			continue
		}
		use.State = UseRetained
		use.Revision++
		use.UpdatedAt = now
		data.Uses[index] = use
		changedGrants[use.GrantID]++
	}
	for grantID, revisionDelta := range changedGrants {
		index, grant, err := findGrant(data.Grants, grantID)
		if err != nil {
			continue
		}
		grant.ReservationRevision += revisionDelta
		data.Grants[index] = aggregateGrantUses(grant, data.Uses)
	}
	return len(changedGrants) > 0
}

func useReservationIsStale(use GrantUse, grant Grant, now time.Time, timeout time.Duration) bool {
	return use.State == UseReserved && reservationCanSettle(grant.Status) &&
		(use.UpdatedAt.IsZero() || !now.Before(use.UpdatedAt.Add(timeout)))
}

func grantCanUse(grant Grant, now time.Time) bool {
	return grant.Status == StatusActive &&
		now.Before(grant.ExpiresAt) &&
		grant.MaxUses.Allows(grant.UsedCount, grant.ReservedCount)
}

func grantCanCommitUse(grant Grant) bool {
	return grant.ReservedCount > 0 && reservationCanSettle(grant.Status)
}

func reservationCanSettle(status Status) bool {
	return status == StatusActive || status == StatusExpired || status == StatusRevoked
}

func (g Grant) toPolicyGrant() policy.Grant {
	usesLeft, finite := g.MaxUses.Remaining(g.UsedCount, g.ReservedCount)
	return policy.Grant{
		ID:        g.ID,
		Client:    g.Client,
		Operation: g.Operation,
		Target: policy.Target{
			Kind:   g.Target.Kind,
			Fields: copyx.StringSliceMap(g.Target.Fields),
		},
		Attrs:     copyx.StringSliceMap(g.Attrs),
		ExpiresAt: g.ExpiresAt,
		UsesLeft:  usesLeft,
		Unlimited: !finite,
	}
}

func findGrant(grants []Grant, id string) (int, Grant, error) {
	for index, grant := range grants {
		if grant.ID == id {
			return index, grant, nil
		}
	}
	return -1, Grant{}, ErrNotFound
}

func findIdempotent(grants []Grant, req Request) (int, Grant, bool) {
	if req.ClientRequestID == "" {
		return -1, Grant{}, false
	}
	for index, grant := range grants {
		if grant.Client == req.Client && grant.ClientRequestID == req.ClientRequestID && grant.Status != StatusCanceled {
			return index, grant, true
		}
	}
	return -1, Grant{}, false
}

func sameRequest(grant Grant, req Request) bool {
	return grant.Operation == req.Operation &&
		targetEqual(grant.Target, req.Target) &&
		mapsEqual(grant.Attrs, req.Attrs) &&
		stringMapsEqual(grant.Metadata, req.Metadata) &&
		grant.Reason == req.Reason && sameRequestBounds(grant, req)
}

func sameRequestBounds(grant Grant, req Request) bool {
	return grant.MaxUses == req.MaxUses &&
		grant.RequestedMaxUsesDefaulted == req.MaxUsesDefaulted &&
		grant.Duration == req.Duration &&
		grant.PendingTimeout == req.PendingTimeout
}

func targetEqual(left policy.Target, right policy.Target) bool {
	return left.Kind == right.Kind && mapsEqual(left.Fields, right.Fields)
}

func mapsEqual(left, right map[string][]string) bool {
	return copyx.StringSliceMapsEqual(left, right)
}

func randomID(bytesCount int) (string, error) {
	data := make([]byte, bytesCount)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
