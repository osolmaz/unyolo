package pairing

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pairingv1 "github.com/osolmaz/unyolo/protocol/pairing"
)

func testInvitationOptions(now time.Time) InvitationOptions {
	return InvitationOptions{
		ID: "pairing-a", Endpoint: "https://pair.example:443", CACertificate: []byte("public-ca"), ServerName: "pair.example",
		ExpiresAt: now.Add(10 * time.Minute),
		Bundle: pairingv1.Bundle{Connections: []pairingv1.BrokerConnection{{
			BrokerName: "gh-broker", ClientID: "bob", Endpoint: "tls://broker.example:443",
			Secret: strings.Repeat("s", 32), ServerName: "broker.example",
		}}},
	}
}

type recordedAudit struct {
	events []Event
}

func (audit *recordedAudit) Emit(event Event) {
	audit.events = append(audit.events, event)
}

func (audit *recordedAudit) names() []string {
	names := make([]string, 0, len(audit.events))
	for _, event := range audit.events {
		names = append(names, event.Name)
	}
	return names
}

func TestPairingTwoPhaseLifecycle(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	audit := &recordedAudit{}
	store := &Store{Directory: filepath.Join(t.TempDir(), "state"), Now: func() time.Time { return now }, Audit: audit}
	encoded, err := store.Create(testInvitationOptions(now))
	if err != nil {
		t.Fatal(err)
	}
	invitation, err := pairingv1.DecodeInvitation(encoded)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := store.Claim(invitation.PairingID, invitation.Token)
	if err != nil || bundle.PairingID != invitation.PairingID || bundle.ClaimSecret == "" {
		t.Fatalf("Claim() = %+v, %v", bundle, err)
	}
	if _, err := store.Claim(invitation.PairingID, invitation.Token); !errors.Is(err, ErrGone) {
		t.Fatalf("replay error = %v", err)
	}
	if _, err := store.Ready(invitation.PairingID, bundle.ClaimSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(invitation.PairingID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verified(invitation.PairingID, bundle.ClaimSecret); err != nil {
		t.Fatal(err)
	}
	record, err := store.LocalStatus(invitation.PairingID)
	if err != nil || record.State != StateVerified || len(record.Bundle.Connections) != 0 || record.ClaimSecretHash != "" {
		t.Fatalf("completed record = %+v, %v", record, err)
	}
	data, err := base64.RawStdEncoding.DecodeString(invitation.CACertificate)
	if err != nil || string(data) != "public-ca" {
		t.Fatalf("invitation CA = %q, %v", data, err)
	}
	expected := []string{EventOffered, EventClaimed, EventDenied, EventReady, EventActive, EventVerified}
	if got := audit.names(); !stringSlicesEqual(got, expected) {
		t.Fatalf("audit events = %v want %v", got, expected)
	}
	for _, event := range audit.events {
		if strings.Contains(event.Reason, bundle.ClaimSecret) || strings.Contains(event.Reason, invitation.Token) {
			t.Fatalf("audit event carries a secret: %+v", event)
		}
	}
}

func TestPairingExpiryAndWrongCredentials(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	clock := now
	store := &Store{Directory: filepath.Join(t.TempDir(), "state"), Now: func() time.Time { return clock }}
	encoded, err := store.Create(testInvitationOptions(now))
	if err != nil {
		t.Fatal(err)
	}
	invitation, _ := pairingv1.DecodeInvitation(encoded)
	if _, err := store.Claim(invitation.PairingID, "wrong"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("wrong token error = %v", err)
	}
	clock = now.Add(11 * time.Minute)
	if _, err := store.Claim(invitation.PairingID, invitation.Token); !errors.Is(err, ErrGone) {
		t.Fatalf("expired token error = %v", err)
	}
	record, err := store.LocalStatus(invitation.PairingID)
	if err != nil || record.State != StateExpired {
		t.Fatalf("expired record = %+v, %v", record, err)
	}
}

func TestPairingWrongTokenEmitsDeniedEvent(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	audit := &recordedAudit{}
	store := &Store{Directory: filepath.Join(t.TempDir(), "state"), Now: func() time.Time { return now }, Audit: audit}
	if _, err := store.Create(testInvitationOptions(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim("pairing-a", "wrong"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("wrong token = %v", err)
	}
	if !stringSlicesContains(audit.names(), EventDenied) {
		t.Fatalf("audit missing denied event: %v", audit.names())
	}
	for _, event := range audit.events {
		if strings.Contains(event.Reason, "wrong") && event.Name != EventDenied {
			continue
		}
		if event.Name == EventDenied && event.Reason == "" {
			t.Fatalf("denied event missing reason: %+v", event)
		}
	}
}

func TestPairingRevokeBeforeActivation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	audit := &recordedAudit{}
	store := &Store{Directory: filepath.Join(t.TempDir(), "state"), Now: func() time.Time { return now }, Audit: audit}
	encoded, err := store.Create(testInvitationOptions(now))
	if err != nil {
		t.Fatal(err)
	}
	invitation, _ := pairingv1.DecodeInvitation(encoded)
	if err := store.Revoke(invitation.PairingID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim(invitation.PairingID, invitation.Token); !errors.Is(err, ErrGone) {
		t.Fatalf("claim after revoke = %v", err)
	}
	record, err := store.LocalStatus(invitation.PairingID)
	if err != nil || record.State != StateRevoked || len(record.Bundle.Connections) != 0 || record.ClaimSecretHash != "" {
		t.Fatalf("revoked record = %+v, %v", record, err)
	}
	if got := audit.names(); !stringSlicesContains(got, EventRevoked) {
		t.Fatalf("audit missing revoke event: %v", got)
	}
}

func TestPairingRevokeRefusedAfterActivation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	store := &Store{Directory: filepath.Join(t.TempDir(), "state"), Now: func() time.Time { return now }}
	encoded, err := store.Create(testInvitationOptions(now))
	if err != nil {
		t.Fatal(err)
	}
	invitation, _ := pairingv1.DecodeInvitation(encoded)
	bundle, err := store.Claim(invitation.PairingID, invitation.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Ready(invitation.PairingID, bundle.ClaimSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(invitation.PairingID); err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(invitation.PairingID); err == nil {
		t.Fatal("revoke after activate must be refused")
	}
}

func TestPairingInterruptedClaimExpiresAndErasesBundle(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	clock := now
	store := &Store{Directory: filepath.Join(t.TempDir(), "state"), Now: func() time.Time { return clock }}
	encoded, err := store.Create(testInvitationOptions(now))
	if err != nil {
		t.Fatal(err)
	}
	invitation, _ := pairingv1.DecodeInvitation(encoded)
	bundle, err := store.Claim(invitation.PairingID, invitation.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Ready(invitation.PairingID, bundle.ClaimSecret); err != nil {
		t.Fatal(err)
	}
	clock = now.Add(2 * time.Hour)
	if _, err := store.Ready(invitation.PairingID, bundle.ClaimSecret); !errors.Is(err, ErrGone) {
		t.Fatalf("ready after completion window = %v", err)
	}
	assertExpiredOnDisk(t, store, invitation.PairingID, bundle)
}

func TestPairingCleanupSweep(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	clock := now
	store := &Store{Directory: filepath.Join(t.TempDir(), "state"), Now: func() time.Time { return clock }}
	pending := testInvitationOptions(now)
	if _, err := store.Create(pending); err != nil {
		t.Fatal(err)
	}
	revoked := pending
	revoked.ID = "pairing-b"
	if _, err := store.Create(revoked); err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(revoked.ID); err != nil {
		t.Fatal(err)
	}
	clock = now.Add(2 * time.Hour)
	changed, err := store.PurgeExpired(30 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if changed != 2 {
		t.Fatalf("purge changed = %d want 2", changed)
	}
	if _, err := os.Lstat(filepath.Join(store.Directory, "pairing-b.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("revoked record retention: err=%v", err)
	}
	data, err := os.ReadFile(filepath.Join(store.Directory, pending.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"state": "expired"`) {
		t.Fatalf("pending after sweep is not expired: %s", data)
	}
}

func assertExpiredOnDisk(t *testing.T, store *Store, id string, bundle pairingv1.Bundle) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(store.Directory, id+".json"))
	if err != nil {
		t.Fatalf("read expired record: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, `"state": "expired"`) {
		t.Fatalf("expected expired state on disk: %s", text)
	}
	if bundle.ClaimSecret != "" && strings.Contains(text, bundle.ClaimSecret) {
		t.Fatal("expired record retains a claim secret")
	}
	for _, connection := range bundle.Connections {
		if strings.Contains(text, connection.Secret) {
			t.Fatal("expired record retains a broker secret")
		}
	}
}

func TestPairingBundleErasureAfterVerified(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	store := &Store{Directory: filepath.Join(t.TempDir(), "state"), Now: func() time.Time { return now }}
	encoded, err := store.Create(testInvitationOptions(now))
	if err != nil {
		t.Fatal(err)
	}
	invitation, _ := pairingv1.DecodeInvitation(encoded)
	bundle, err := store.Claim(invitation.PairingID, invitation.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Ready(invitation.PairingID, bundle.ClaimSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(invitation.PairingID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verified(invitation.PairingID, bundle.ClaimSecret); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(store.Directory, invitation.PairingID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), bundle.ClaimSecret) || strings.Contains(string(data), bundle.Connections[0].Secret) {
		t.Fatal("verified record retains a secret on disk")
	}
}

func stringSlicesEqual(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

func stringSlicesContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
