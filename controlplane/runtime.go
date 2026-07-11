// Package controlplane assembles Brokerkit's shared broker control plane.
package controlplane

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/osolmaz/brokerkit/approval"
	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/auth"
	"github.com/osolmaz/brokerkit/decision"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
	"github.com/osolmaz/brokerkit/operatorapi"
	"github.com/osolmaz/brokerkit/operatorauth"
	"github.com/osolmaz/brokerkit/operatorinbox"
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
}

// New validates and assembles one broker control plane.
func New(options Options) (*Runtime, error) {
	if strings.TrimSpace(options.Broker) == "" {
		return nil, errors.New("broker name is required")
	}
	if options.Store == nil {
		return nil, errors.New("grant store is required")
	}
	clients, err := auth.New(options.ClientSecrets, auth.Options{})
	if err != nil {
		return nil, err
	}
	recorder := options.Audit
	if recorder == nil {
		recorder = audit.New(io.Discard)
	}
	options.Audit = recorder
	decisions, err := decision.New(decision.Options{
		Store: options.Store, Validator: options.ActivationValidator, Broker: options.Broker, Audit: recorder,
	})
	if err != nil {
		return nil, err
	}
	handler, err := operatorHandler(options, decisions)
	if err != nil {
		return nil, err
	}
	decider := channelDecider{service: decisions}
	return &Runtime{Store: options.Store, Clients: clients, OperatorHandler: handler, Decider: decider, Decisions: decisions}, nil
}

func operatorHandler(options Options, decisions *decision.Service) (http.Handler, error) {
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
	recorder := options.Audit
	if recorder == nil {
		recorder = audit.New(io.Discard)
	}
	return operatorapi.New(operatorapi.Options{
		Inbox: inbox, Decisions: decisions, Authorize: operators.AuthenticateRequest, Broker: options.Broker, Audit: recorder,
	})
}

type channelDecider struct{ service *decision.Service }

func (d channelDecider) Approve(ctx context.Context, id, token, actor string, ref notify.MessageRef) (grants.Grant, error) {
	return d.service.ApproveToken(ctx, id, token, actor, ref)
}

func (d channelDecider) Deny(ctx context.Context, id, token, actor string, ref notify.MessageRef) (grants.Grant, error) {
	return d.service.DenyToken(ctx, id, token, actor, ref)
}
