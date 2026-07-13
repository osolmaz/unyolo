// Package operations owns Hugging Face operation adapters and their registry.
package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
)

type Input struct {
	Target    json.RawMessage
	Arguments json.RawMessage
}

// Plan is the provider-owned portion of the immutable execution envelope.
type Plan struct {
	Operation         string
	OperationRevision int
	Target            json.RawMessage
	Arguments         json.RawMessage
	Preconditions     json.RawMessage
	Presentation      agentv1.Presentation
	Policy            hfpolicy.Request
}

type Outcome struct {
	Proven bool
	Result json.RawMessage
}

type Adapter interface {
	Descriptor() opcatalog.Descriptor
	Decode(target, arguments json.RawMessage) (Input, error)
	Resolve(context.Context, Input) (Plan, error)
	Authorize(Plan) hfpolicy.Request
	Present(Plan) agentv1.Presentation
	Execute(context.Context, Plan) (json.RawMessage, error)
	Reconcile(context.Context, Plan) (Outcome, error)
}

type Registry struct {
	byName map[string]Adapter
	names  []string
}

func NewRegistry(adapters ...Adapter) (*Registry, error) {
	registry := &Registry{byName: make(map[string]Adapter, len(adapters))}
	for _, adapter := range adapters {
		if adapter == nil {
			return nil, errors.New("nil Hugging Face operation adapter")
		}
		descriptor := adapter.Descriptor()
		canonical, found := opcatalog.ByName(descriptor.Name)
		if !found || canonical != descriptor || canonical.AuthorizationMode != opcatalog.ModeExecution {
			return nil, fmt.Errorf("adapter %q does not match the capability catalog", descriptor.Name)
		}
		if _, exists := registry.byName[descriptor.Name]; exists {
			return nil, fmt.Errorf("duplicate adapter %q", descriptor.Name)
		}
		registry.byName[descriptor.Name] = adapter
		registry.names = append(registry.names, descriptor.Name)
	}
	slices.Sort(registry.names)
	return registry, nil
}

func (r *Registry) Lookup(name string) (Adapter, bool) {
	if r == nil {
		return nil, false
	}
	adapter, found := r.byName[name]
	return adapter, found
}

func (r *Registry) Names() []string {
	if r == nil {
		return nil
	}
	return slices.Clone(r.names)
}

// ValidateCoverage ensures every catalog entry advertised as an implemented
// execution operation has an adapter. Existing bounded protocol operations do
// not enter this registry.
func (r *Registry) ValidateCoverage() error {
	var missing []string
	for _, descriptor := range opcatalog.MustAll() {
		if descriptor.AuthorizationMode != opcatalog.ModeExecution || descriptor.Implementation != opcatalog.StatusImplemented {
			continue
		}
		if _, found := r.Lookup(descriptor.Name); !found {
			missing = append(missing, descriptor.Name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing Hugging Face operation adapters: %s", strings.Join(missing, ", "))
	}
	return nil
}

type client interface {
	Do(context.Context, hubclient.Call) (hubclient.Response, error)
}
