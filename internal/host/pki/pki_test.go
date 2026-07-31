package pki

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestGenerateCAAndIssueServer(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	ca, err := GenerateCA(now, 0)
	if err != nil {
		t.Fatal(err)
	}
	server, err := IssueServer(ca, []string{"broker.example", "127.0.0.1"}, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(server.Certificate, server.PrivateKey); err != nil {
		t.Fatalf("server key pair: %v", err)
	}
	block, _ := pem.Decode(server.Certificate)
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.Certificate) {
		t.Fatal("append CA")
	}
	for _, name := range []string{"broker.example", "127.0.0.1"} {
		if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, DNSName: name, CurrentTime: now}); err != nil {
			t.Fatalf("verify %s: %v", name, err)
		}
	}
}

func TestIssueServerRejectsInvalidCAAndNames(t *testing.T) {
	t.Parallel()
	now := time.Now()
	if _, err := IssueServer(Material{}, []string{"broker.example"}, now, 0); err == nil {
		t.Fatal("invalid CA accepted")
	}
	ca, err := GenerateCA(now, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, names := range [][]string{nil, {"bad/name"}, {"same", "same"}} {
		if _, err := IssueServer(ca, names, now, 0); err == nil {
			t.Fatalf("invalid names accepted: %#v", names)
		}
	}
}
