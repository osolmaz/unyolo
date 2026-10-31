package main

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/osolmaz/unyolo/deployment/api"
	"github.com/osolmaz/unyolo/deployment/flow"
	"github.com/osolmaz/unyolo/internal/host/pki"
	"github.com/osolmaz/unyolo/setup/installation"
	setupintent "github.com/osolmaz/unyolo/setup/intent"
	"github.com/osolmaz/unyolo/setup/sandbox/openshell"
)

const (
	sandboxCertificateSuffix = "-sandbox-tls-certificate"
	sandboxKeySuffix         = "-sandbox-tls-key" // #nosec G101 -- public credential slot suffix, not a credential.
	// sandboxCertificateLifetime is how long a sandbox listener certificate
	// is valid. A new certificate comes with a new CA, which the OpenShell
	// gateway reads only when it restarts.
	sandboxCertificateLifetime = 2 * 365 * 24 * time.Hour
	sandboxListenerWait        = 30 * time.Second
)

// sandboxAdapter is replaced in tests.
var sandboxAdapter = func() (openshell.Adapter, error) {
	home, err := os.UserConfigDir()
	if err != nil {
		return openshell.Adapter{}, err
	}
	return openshell.Adapter{Runner: openshell.ExecRunner{}, ConfigHome: home}, nil
}

// issueSandboxTLS issues a listener certificate for each component whose
// sandbox TLS slots the plan installs. One CA signs them all, limited to the
// listener names, and its key is cleared once they are signed, so the CA can
// never sign anything else. It returns the slot values and the CA certificate.
func issueSandboxTLS(slots []string, now time.Time) (map[string][]byte, []byte, error) {
	var components []string
	for _, slot := range slots {
		if component, found := strings.CutSuffix(slot, sandboxCertificateSuffix); found {
			components = append(components, component)
		}
	}
	if len(components) == 0 {
		return nil, nil, nil
	}
	ca, err := pki.GenerateConstrainedCA(now, sandboxCertificateLifetime+24*time.Hour, openshell.ServerNames)
	if err != nil {
		return nil, nil, err
	}
	defer clear(ca.PrivateKey)
	values := map[string][]byte{}
	for _, component := range components {
		if !slices.Contains(slots, component+sandboxKeySuffix) {
			return nil, nil, fmt.Errorf("the plan installs the %s sandbox listener certificate without its key", component)
		}
		server, err := pki.IssueServer(ca, openshell.ServerNames, now, sandboxCertificateLifetime)
		if err != nil {
			return nil, nil, err
		}
		values[component+sandboxCertificateSuffix], values[component+sandboxKeySuffix] = server.Certificate, server.PrivateKey
	}
	return values, ca.Certificate, nil
}

// sandboxConnections returns the installation's OpenShell connections with
// the sandbox access that each of their providers declares.
func sandboxConnections(desired installation.Installation, metadata []api.RenderMetadata) ([]openshell.Connection, error) {
	declared := map[string]*api.RenderSandboxAccess{}
	for _, value := range metadata {
		declared[value.ComponentID] = value.SandboxAccess
	}
	var result []openshell.Connection
	for _, connection := range desired.Connections {
		if connection.Target.Kind != installation.TargetSandbox {
			continue
		}
		if connection.Target.Runtime != setupintent.SandboxOpenShell {
			return nil, fmt.Errorf("connection %s uses an unsupported sandbox runtime", connection.ID)
		}
		value := openshell.Connection{ID: connection.ClientID, Sandbox: connection.Target.Sandbox}
		for _, provider := range connection.Providers {
			access := declared[provider]
			if access == nil {
				return nil, fmt.Errorf("the %s provider declares no sandbox access for connection %s", provider, connection.ID)
			}
			value.Accesses = append(value.Accesses, openshell.Access{ProviderID: provider, Declared: *access})
		}
		if len(value.Accesses) == 0 {
			return nil, fmt.Errorf("connection %s has no provider that serves sandboxes", connection.ID)
		}
		result = append(result, value)
	}
	return result, nil
}

// checkSandboxRuntimes verifies the sandbox runtimes before any administrator
// change, so an unsupported OpenShell fails early.
func checkSandboxRuntimes(ctx context.Context, connections []openshell.Connection) error {
	if len(connections) == 0 {
		return nil
	}
	adapter, err := sandboxAdapter()
	if err != nil {
		return err
	}
	probe, err := pki.GenerateConstrainedCA(time.Now(), time.Hour, openshell.ServerNames)
	if err != nil {
		return err
	}
	clear(probe.PrivateKey)
	return adapter.Check(ctx, probe.Certificate)
}

// connectSandboxes runs after the administrator changes. It checks each
// sandbox listener with its new client secret, makes the OpenShell resources,
// and tells the owner what the sandbox still needs.
func connectSandboxes(ctx context.Context, prompter flow.SetupPrompter, connections []openshell.Connection, secrets map[string][]byte, caBundle []byte) error {
	if len(connections) == 0 {
		return nil
	}
	adapter, err := sandboxAdapter()
	if err != nil {
		return err
	}
	for _, connection := range connections {
		for index, access := range connection.Accesses {
			secret := secrets[access.ProviderID+"-client-"+connection.ID]
			if secret == nil {
				continue
			}
			connection.Accesses[index].ClientSecret = secret
			if caBundle != nil {
				if err := openshell.VerifyListener(ctx, connection.Accesses[index], caBundle, sandboxListenerWait); err != nil {
					return err
				}
			}
		}
		result, err := adapter.Connect(ctx, connection, caBundle)
		if err != nil {
			return err
		}
		if err := prompter.Note(ctx, sandboxConnectionNote(connection.Sandbox, result), "OpenShell sandbox "+connection.Sandbox); err != nil {
			return err
		}
	}
	return nil
}

func sandboxConnectionNote(sandbox string, result openshell.Result) string {
	lines := []string{"OpenShell providers: " + strings.Join(result.Providers, ", "), "Sandbox environment: " + result.EnvironmentFile}
	if result.GatewayRestarted {
		lines = append(lines, "The OpenShell gateway restarted to trust the new sandbox listener CA.")
	}
	switch {
	case result.SandboxMissing:
		lines = append(lines, "The sandbox does not exist yet. Create it with these options:", sandboxCreateOptions(result))
	case result.SandboxRecreate:
		lines = append(lines, "The sandbox lacks the environment. Delete it and create it again with these options:", sandboxCreateOptions(result))
	default:
		lines = append(lines, "The sandbox "+sandbox+" is connected.")
	}
	return strings.Join(lines, "\n")
}

func sandboxCreateOptions(result openshell.Result) string {
	options := make([]string, 0, len(result.Providers)+len(result.Environment))
	for _, provider := range result.Providers {
		options = append(options, "--provider "+provider)
	}
	for _, variable := range result.Environment {
		options = append(options, "--env "+strconv.Quote(variable.Name+"="+variable.Value))
	}
	return "  " + strings.Join(options, " \\\n  ")
}
