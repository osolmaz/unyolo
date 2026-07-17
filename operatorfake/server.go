// Package operatorfake provides a real in-process operator API for consumer tests.
package operatorfake

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/osolmaz/brokerkit/approvalview"
	"github.com/osolmaz/brokerkit/controlplane"
	"github.com/osolmaz/brokerkit/decision"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operatorapi"
	"github.com/osolmaz/brokerkit/operatorclient"
)

// Options configures a fake server with production handlers and storage behavior.
type Options struct {
	Store               *grants.Store
	Presenter           approvalview.Presenter
	OperatorSecrets     map[string]string
	ClientSecrets       map[string]string
	Broker              string
	Audit               operatorapi.AuditRecorder
	ActivationValidator decision.ActivationValidator
}

// Server is one closeable in-process operator API.
type Server struct {
	server *httptest.Server
}

// New starts a fake operator server.
func New(options Options) (*Server, error) {
	if options.Store == nil {
		return nil, errors.New("grant store is required")
	}
	if len(options.OperatorSecrets) == 0 {
		return nil, errors.New("at least one operator secret is required")
	}
	if options.Audit == nil {
		return nil, errors.New("test audit recorder is required")
	}
	if options.Broker == "" {
		options.Broker = "fake-broker"
	}
	clientSecrets := options.ClientSecrets
	if len(clientSecrets) == 0 {
		clientSecrets = map[string]string{"fixture-client": "operatorfake-client-secret-not-for-production"}
	}
	runtime, err := controlplane.New(controlplane.Options{
		Store: options.Store, Presenter: options.Presenter,
		ClientSecrets: clientSecrets, OperatorSecrets: options.OperatorSecrets,
		Broker: options.Broker, Audit: options.Audit,
		ActivationValidator: options.ActivationValidator,
	})
	if err != nil {
		return nil, err
	}
	return &Server{server: httptest.NewServer(runtime.OperatorHandler)}, nil
}

// Client returns a client configured for this fake server.
func (s *Server) Client(token string) *operatorclient.Client {
	client, err := operatorclient.New(strings.Replace(s.server.URL, "http://", "tcp://", 1), token, s.server.Client())
	if err != nil {
		panic(err)
	}
	return client
}

// HTTPClient returns the in-process server transport for raw protocol tests.
func (s *Server) HTTPClient() *http.Client { return s.server.Client() }

// URL returns the fake server base URL for non-Go fixture consumers.
func (s *Server) URL() string { return s.server.URL }

// Close stops the fake server.
func (s *Server) Close() { s.server.Close() }
