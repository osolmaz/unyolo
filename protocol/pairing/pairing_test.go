package pairing

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestInvitationRoundTrip(t *testing.T) {
	t.Parallel()
	certificate := []byte("public certificate")
	value := Invitation{
		APIVersion: APIVersion, Endpoint: "https://pair.example:443", PairingID: "pair-a",
		Token:         base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		CACertificate: base64.RawStdEncoding.EncodeToString(certificate),
		CAFingerprint: fmt.Sprintf("sha256:%x", sha256.Sum256(certificate)), ServerName: "pair.example",
		ExpiresAt: time.Now().Add(time.Minute).UTC(),
	}
	encoded, err := EncodeInvitation(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeInvitation(encoded)
	if err != nil || decoded.PairingID != value.PairingID {
		t.Fatalf("DecodeInvitation() = %+v, %v", decoded, err)
	}
}

func TestBundleRejectsCredentialAndEndpointErrors(t *testing.T) {
	t.Parallel()
	base := Bundle{
		APIVersion: APIVersion, PairingID: "pair-a",
		ClaimSecret: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), CACertificate: base64.RawStdEncoding.EncodeToString([]byte("ca")),
		Connections: []BrokerConnection{{BrokerName: "gh-broker", ClientID: "bob", Endpoint: "tls://broker.example:443", Secret: strings.Repeat("s", 32), ServerName: "broker.example"}},
	}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	base.Connections[0].Endpoint = "tcp://broker.example:443"
	if err := base.Validate(); err == nil {
		t.Fatal("plaintext endpoint accepted")
	}
}
