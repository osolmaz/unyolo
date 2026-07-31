package pairing

import (
	"encoding/base64"
	"errors"
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

func TestPairingTwoPhaseLifecycle(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	store := &Store{Directory: filepath.Join(t.TempDir(), "state"), Now: func() time.Time { return now }}
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
