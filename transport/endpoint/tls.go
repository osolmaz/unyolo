package endpoint

import (
	"crypto/tls"
	"errors"
	"path/filepath"
)

// ServerTLSConfig loads one server certificate and enforces TLS 1.3.
func ServerTLSConfig(certificateFile, privateKeyFile string) (*tls.Config, error) {
	if !cleanAbsolute(certificateFile) || !cleanAbsolute(privateKeyFile) || certificateFile == privateKeyFile {
		return nil, errors.New("TLS certificate and private key paths must be distinct, absolute, and clean")
	}
	certificate, err := tls.LoadX509KeyPair(certificateFile, privateKeyFile)
	if err != nil {
		return nil, errors.New("load TLS server certificate")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}, nil
}

func cleanAbsolute(value string) bool { return filepath.IsAbs(value) && filepath.Clean(value) == value }
