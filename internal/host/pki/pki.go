// Package pki creates installation-local certificate authorities and broker server certificates.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

const (
	DefaultCALifetime     = 10 * 365 * 24 * time.Hour
	DefaultServerLifetime = 90 * 24 * time.Hour
)

type Material struct {
	Certificate []byte
	PrivateKey  []byte
}

func GenerateCA(now time.Time, lifetime time.Duration) (Material, error) {
	if lifetime <= 0 {
		lifetime = DefaultCALifetime
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Material{}, fmt.Errorf("generate installation CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return Material{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "unYOLO installation CA"},
		NotBefore: now.UTC().Add(-time.Minute), NotAfter: now.UTC().Add(lifetime),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	return createMaterial(template, template, &key.PublicKey, key, key)
}

func IssueServer(ca Material, names []string, now time.Time, lifetime time.Duration) (Material, error) {
	certificate, caKey, err := parseCA(ca)
	if err != nil {
		return Material{}, err
	}
	if lifetime <= 0 {
		lifetime = DefaultServerLifetime
	}
	if len(names) == 0 || len(names) > 32 {
		return Material{}, errors.New("server certificate requires 1 to 32 names")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Material{}, fmt.Errorf("generate server key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return Material{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: names[0]},
		NotBefore: now.UTC().Add(-time.Minute), NotAfter: now.UTC().Add(lifetime),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	seen := map[string]bool{}
	for _, name := range names {
		if name == "" || len(name) > 253 || strings.ContainsAny(name, "\x00\r\n/") || seen[name] {
			return Material{}, errors.New("server certificate name is invalid or duplicated")
		}
		seen[name] = true
		if ip := net.ParseIP(name); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, name)
		}
	}
	if template.NotAfter.After(certificate.NotAfter) {
		template.NotAfter = certificate.NotAfter
	}
	return createMaterial(template, certificate, &key.PublicKey, caKey, key)
}

func createMaterial(template, parent *x509.Certificate, publicKey any, signer, materialKey *ecdsa.PrivateKey) (Material, error) {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signer)
	if err != nil {
		return Material{}, fmt.Errorf("create certificate: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(materialKey)
	if err != nil {
		return Material{}, fmt.Errorf("marshal private key: %w", err)
	}
	return Material{
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKey:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
	}, nil
}

func parseCA(value Material) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certificateBlock, rest := pem.Decode(value.Certificate)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, nil, errors.New("installation CA certificate is invalid")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil || !certificate.IsCA {
		return nil, nil, errors.New("installation CA certificate is invalid")
	}
	keyBlock, rest := pem.Decode(value.PrivateKey)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, nil, errors.New("installation CA private key is invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || !key.PublicKey.Equal(certificate.PublicKey) {
		return nil, nil, errors.New("installation CA private key is invalid")
	}
	return certificate, key, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	if serial.Sign() == 0 {
		return randomSerial()
	}
	return serial, nil
}
