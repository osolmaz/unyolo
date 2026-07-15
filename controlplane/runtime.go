// Package controlplane assembles Brokerkit's shared broker control plane.
package controlplane

import (
	"context"
	"errors"
	"net/http"

	"github.com/osolmaz/brokerkit/approval"
	"github.com/osolmaz/brokerkit/auth"
	"github.com/osolmaz/brokerkit/decision"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
	"github.com/osolmaz/brokerkit/observability"
	"github.com/osolmaz/brokerkit/operatorapi"
	"github.com/osolmaz/brokerkit/operatorauth"
	"github.com/osolmaz/brokerkit/operatorinbox"
	"github.com/osolmaz/brokerkit/state"
)

// Options provides broker-owned policy vocabulary and presentation to the shared runtime.
type Options struct {
	Broker              string
	Store               *grants.Store
	ClientSecrets       map[string]string
	OperatorSecrets     map[string]string
	Presenter           operatorinbox.Presenter
	Audit               operatorapi.AuditRecorder
	ActivationValidator decision.ActivationValidator
	NewCorrelationID    func() (string, error)
	State               *state.Database
}

// HandleDecision applies one approval-channel callback through the configured decider.
func (r *Runtime) HandleDecision(ctx context.Context, decision notify.Decision) notify.DecisionResult {
	return approval.HandleDecision(ctx, r.Decider, decision)
}

// Runtime contains the shared state and protected HTTP surfaces for one broker.
type Runtime struct {
	Store           *grants.Store
	Clients         *auth.Authenticator
	OperatorHandler http.Handler
	Decider         approval.Decider
	Decisions       *decision.Service
	Metrics         *observability.Metrics
	Diagnostics     *observability.Diagnostics
}

// New validates and assembles one broker control plane.
func New(options Options) (*Runtime, error) {
	if options.Store == nil {
		return nil, errors.New("grant store is required")
	}
	if options.Audit == nil {
		return nil, errors.New("audit recorder is required")
	}
	clients, err := auth.New(options.ClientSecrets, auth.Options{})
	if err != nil {
		return nil, err
	}
	metrics, err := observability.New(options.Broker, options.State)
	if err != nil {
		return nil, err
	}
	diagnostics := observability.NewDiagnostics(options.Broker, metrics, nil)
	decisions, err := decision.New(decision.Options{
		Store: options.Store, Validator: options.ActivationValidator, Broker: options.Broker, Audit: options.Audit, Observer: metrics,
	})
	if err != nil {
		return nil, err
	}
	handler, err := operatorHandler(options, decisions, metrics)
	if err != nil {
		return nil, err
	}
	decider := channelDecider{service: decisions}
	return &Runtime{Store: options.Store, Clients: clients, OperatorHandler: handler, Decider: decider, Decisions: decisions, Metrics: metrics, Diagnostics: diagnostics}, nil
}

func operatorHandler(options Options, decisions *decision.Service, metrics *observability.Metrics) (http.Handler, error) {
	if len(options.OperatorSecrets) == 0 {
		return nil, nil
	}
	operators, err := operatorauth.New(options.OperatorSecrets, operatorauth.Options{ClientSecrets: options.ClientSecrets})
	if err != nil {
		return nil, err
	}
	inbox, err := operatorinbox.New(options.Store, options.Presenter)
	if err != nil {
		return nil, err
	}
	return operatorapi.New(operatorapi.Options{
		Inbox: inbox, Decisions: decisions, Authorize: operators.AuthenticateRequest, Broker: options.Broker, Audit: options.Audit,
		NewCorrelationID: options.NewCorrelationID, Metrics: metrics.Handler(),
	})
}

type channelDecider struct{ service *decision.Service }

func (d channelDecider) Approve(ctx context.Context, id, token, actor string, ref notify.MessageRef) (grants.Grant, error) {
	return d.service.ApproveToken(ctx, id, token, actor, ref)
}

func (d channelDecider) Deny(ctx context.Context, id, token, actor string, ref notify.MessageRef) (grants.Grant, error) {
	return d.service.DenyToken(ctx, id, token, actor, ref)
}
