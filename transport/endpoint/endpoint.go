// Package endpoint defines provider-neutral broker listener and client endpoints.
package endpoint

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Scheme identifies how an endpoint is acquired.
type Scheme string

const (
	SchemeUnix       Scheme = "unix"
	SchemeTCP        Scheme = "tcp"
	SchemeActivation Scheme = "activation"
	SchemeFD         Scheme = "fd"
)

// Exposure classifies the network reachability of an endpoint.
type Exposure string

const (
	ExposureLocal    Exposure = "local"
	ExposureLoopback Exposure = "loopback"
	ExposureNetwork  Exposure = "network"
)

// ParseOptions controls deployment-sensitive endpoint validation.
type ParseOptions struct {
	AllowEphemeralTCP bool
	AllowNetworkTCP   bool
}

// Endpoint is one validated canonical listener or client endpoint.
type Endpoint struct {
	scheme   Scheme
	path     string
	host     string
	port     int
	name     string
	fd       int
	exposure Exposure
}

// Parse validates a complete endpoint URI.
func Parse(value string, options ParseOptions) (Endpoint, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return Endpoint{}, errors.New("endpoint URI is required without surrounding whitespace")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return Endpoint{}, errors.New("endpoint URI is invalid")
	}
	parser, found := endpointParsers[Scheme(parsed.Scheme)]
	if !found {
		return Endpoint{}, fmt.Errorf("endpoint scheme %q is unsupported", parsed.Scheme)
	}
	return parser(parsed, options)
}

var endpointParsers = map[Scheme]func(*url.URL, ParseOptions) (Endpoint, error){
	SchemeUnix:       func(value *url.URL, _ ParseOptions) (Endpoint, error) { return parseUnix(value) },
	SchemeTCP:        parseTCP,
	SchemeActivation: func(value *url.URL, _ ParseOptions) (Endpoint, error) { return parseActivation(value) },
	SchemeFD:         func(value *url.URL, _ ParseOptions) (Endpoint, error) { return parseFD(value) },
}

func parseUnix(parsed *url.URL) (Endpoint, error) {
	if parsed.Host != "" || !filepath.IsAbs(parsed.Path) || filepath.Clean(parsed.Path) != parsed.Path || parsed.Path == string(filepath.Separator) {
		return Endpoint{}, errors.New("unix endpoint must contain one absolute normalized socket path")
	}
	return Endpoint{scheme: SchemeUnix, path: parsed.Path, exposure: ExposureLocal}, nil
}

func parseTCP(parsed *url.URL, options ParseOptions) (Endpoint, error) {
	if parsed.Path != "" || parsed.Opaque != "" || parsed.Host == "" {
		return Endpoint{}, errors.New("tcp endpoint must contain only an explicit host and port")
	}
	host, rawPort, err := splitTCPHostPort(parsed.Host)
	if err != nil {
		return Endpoint{}, err
	}
	port, err := parseTCPPort(rawPort, options.AllowEphemeralTCP)
	if err != nil {
		return Endpoint{}, err
	}
	ip, err := parseTCPHost(host)
	if err != nil {
		return Endpoint{}, err
	}
	exposure, err := classifyTCP(ip, options.AllowNetworkTCP)
	if err != nil {
		return Endpoint{}, err
	}
	return Endpoint{scheme: SchemeTCP, host: ip.String(), port: port, exposure: exposure}, nil
}

func splitTCPHostPort(address string) (string, string, error) {
	host, rawPort, err := net.SplitHostPort(address)
	if err != nil || host == "" || rawPort == "" {
		return "", "", errors.New("tcp endpoint must contain an explicit unambiguous host and port")
	}
	return host, rawPort, nil
}

func parseTCPHost(host string) (net.IP, error) {
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, errors.New("tcp endpoint host must be a literal IP address")
	}
	return ip, nil
}

func parseTCPPort(raw string, allowEphemeral bool) (int, error) {
	port, err := strconv.Atoi(raw)
	if err != nil || port < 0 || port > 65535 || port == 0 && !allowEphemeral {
		return 0, errors.New("tcp endpoint port must be between 1 and 65535")
	}
	return port, nil
}

func classifyTCP(ip net.IP, allowNetwork bool) (Exposure, error) {
	if ip.IsLoopback() {
		return ExposureLoopback, nil
	}
	if !allowNetwork {
		return "", errors.New("non-loopback tcp endpoint requires explicit network exposure approval")
	}
	return ExposureNetwork, nil
}

func parseActivation(parsed *url.URL) (Endpoint, error) {
	if parsed.Path != "" || parsed.Host == "" || !validName(parsed.Host) {
		return Endpoint{}, errors.New("activation endpoint must contain one safe listener name")
	}
	return Endpoint{scheme: SchemeActivation, name: parsed.Host, exposure: ExposureLocal}, nil
}

func parseFD(parsed *url.URL) (Endpoint, error) {
	if parsed.Path != "" || parsed.Host == "" {
		return Endpoint{}, errors.New("fd endpoint must contain one inherited descriptor number")
	}
	fd, err := strconv.Atoi(parsed.Host)
	if err != nil || fd < 3 {
		return Endpoint{}, errors.New("inherited descriptor must be at least 3")
	}
	return Endpoint{scheme: SchemeFD, fd: fd, exposure: ExposureLocal}, nil
}

var safeNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func validName(value string) bool { return safeNamePattern.MatchString(value) }

func (e Endpoint) String() string {
	switch e.scheme {
	case SchemeUnix:
		return "unix://" + e.path
	case SchemeTCP:
		return "tcp://" + net.JoinHostPort(e.host, strconv.Itoa(e.port))
	case SchemeActivation:
		return "activation://" + e.name
	case SchemeFD:
		return "fd://" + strconv.Itoa(e.fd)
	default:
		return ""
	}
}

func (e Endpoint) Scheme() Scheme         { return e.scheme }
func (e Endpoint) Exposure() Exposure     { return e.exposure }
func (e Endpoint) Path() string           { return e.path }
func (e Endpoint) ActivationName() string { return e.name }
func (e Endpoint) Descriptor() int        { return e.fd }

// Address returns the concrete TCP address. Other schemes return an empty string.
func (e Endpoint) Address() string {
	if e.scheme != SchemeTCP {
		return ""
	}
	return net.JoinHostPort(e.host, strconv.Itoa(e.port))
}

// ClientCapable reports whether clients can dial the endpoint directly.
func (e Endpoint) ClientCapable() bool { return e.scheme == SchemeUnix || e.scheme == SchemeTCP }

// Ephemeral reports whether e asks the operating system to allocate a TCP port.
func (e Endpoint) Ephemeral() bool { return e.scheme == SchemeTCP && e.port == 0 }

// Resolved returns the concrete endpoint represented by an acquired listener.
// It resolves development port zero while preserving stable Unix and activated names.
func Resolved(configured Endpoint, listener net.Listener) (Endpoint, error) {
	if listener == nil {
		return Endpoint{}, errors.New("listener is required")
	}
	if configured.scheme != SchemeTCP || configured.port != 0 {
		return configured, nil
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address.Port < 1 {
		return Endpoint{}, errors.New("ephemeral TCP listener has an invalid address")
	}
	host := configured.host
	if host == "" {
		host = address.IP.String()
	}
	return Endpoint{scheme: SchemeTCP, host: host, port: address.Port, exposure: configured.exposure}, nil
}
