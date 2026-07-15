package setup

import (
	"errors"
	"fmt"

	"github.com/osolmaz/brokerkit/endpoint"
	"github.com/osolmaz/brokerkit/service"
)

// SystemdActivation describes the socket units and local access groups for one
// broker service installation.
type SystemdActivation struct {
	Sockets         []service.SystemdSocketInstall
	Groups          []string
	GroupMembers    map[string][]string
	ActivationUnits []string
}

// LaunchdActivation describes named launchd sockets and their local access
// groups. The service consumes activation://agent and activation://operator;
// clients retain concrete Unix endpoint URIs.
type LaunchdActivation struct {
	Sockets      []service.LaunchdSocket
	Groups       []string
	GroupMembers map[string][]string
}

// BuildLaunchdActivation builds permission-separated agent and operator
// sockets for one system LaunchDaemon.
func BuildLaunchdActivation(opts SystemdOptions, operatorEndpoint string) (LaunchdActivation, error) {
	opts = activationDefaults(opts)
	agent, operator, err := concreteActivationEndpoints(opts.Endpoint, operatorEndpoint, "launchd")
	if err != nil {
		return LaunchdActivation{}, err
	}
	sockets := []service.LaunchdSocket{
		launchdSocket("agent", agent.Path(), opts.AgentAccessGroup),
		launchdSocket("operator", operator.Path(), opts.OperatorAccessGroup),
	}
	return LaunchdActivation{
		Sockets: sockets,
		Groups:  []string{opts.AgentAccessGroup, opts.OperatorAccessGroup},
		GroupMembers: map[string][]string{
			opts.AgentAccessGroup:    {opts.AgentUser},
			opts.OperatorAccessGroup: {opts.OperatorUser},
		},
	}, nil
}

// BuildSystemdActivation builds permission-separated agent and operator Unix
// socket activation. The client-facing endpoints remain concrete Unix URIs;
// the service consumes the descriptors as activation://agent and
// activation://operator.
func BuildSystemdActivation(opts SystemdOptions, operatorEndpoint, serviceUnit string) (SystemdActivation, error) {
	opts = activationDefaults(opts)
	agent, operator, err := concreteActivationEndpoints(opts.Endpoint, operatorEndpoint, "systemd")
	if err != nil {
		return SystemdActivation{}, err
	}
	sockets := []service.SystemdSocketInstall{
		activationSocket(opts.BrokerName+"-agent.socket", "agent", agent.Path(), opts.AgentAccessGroup, serviceUnit),
		activationSocket(opts.BrokerName+"-operator.socket", "operator", operator.Path(), opts.OperatorAccessGroup, serviceUnit),
	}
	return SystemdActivation{
		Sockets: sockets,
		Groups:  []string{opts.AgentAccessGroup, opts.OperatorAccessGroup},
		GroupMembers: map[string][]string{
			opts.AgentAccessGroup:    {opts.AgentUser},
			opts.OperatorAccessGroup: {opts.OperatorUser},
		},
		ActivationUnits: []string{sockets[0].UnitName, sockets[1].UnitName, serviceUnit},
	}, nil
}

func concreteActivationEndpoints(agentURI, operatorURI, manager string) (endpoint.Endpoint, endpoint.Endpoint, error) {
	agent, err := endpoint.Parse(agentURI, endpoint.ParseOptions{})
	if err != nil {
		return endpoint.Endpoint{}, endpoint.Endpoint{}, fmt.Errorf("agent endpoint: %w", err)
	}
	operator, err := endpoint.Parse(operatorURI, endpoint.ParseOptions{})
	if err != nil {
		return endpoint.Endpoint{}, endpoint.Endpoint{}, fmt.Errorf("operator endpoint: %w", err)
	}
	if agent.Scheme() != endpoint.SchemeUnix || operator.Scheme() != endpoint.SchemeUnix {
		return endpoint.Endpoint{}, endpoint.Endpoint{}, fmt.Errorf("%s setup requires concrete Unix client endpoints", manager)
	}
	if agent.Path() == operator.Path() {
		return endpoint.Endpoint{}, endpoint.Endpoint{}, errors.New("agent and operator socket paths must differ")
	}
	return agent, operator, nil
}

func activationDefaults(opts SystemdOptions) SystemdOptions {
	if opts.AgentAccessGroup == "" {
		opts.AgentAccessGroup = opts.BrokerName + "-agent"
	}
	if opts.OperatorAccessGroup == "" {
		opts.OperatorAccessGroup = opts.BrokerName + "-operator"
	}
	if opts.AgentUser == "" {
		opts.AgentUser = opts.User
	}
	if opts.OperatorUser == "" {
		opts.OperatorUser = opts.User
	}
	return opts
}

func activationSocket(unitName, descriptor, path, group, serviceUnit string) service.SystemdSocketInstall {
	return service.SystemdSocketInstall{UnitName: unitName, Unit: service.SystemdSocketUnit{
		Description:  "BrokerKit " + descriptor + " listener",
		ListenStream: path, Service: serviceUnit, FileDescriptorName: descriptor,
		SocketUser: "root", SocketGroup: group, SocketMode: 0o660, DirectoryMode: 0o711,
	}}
}

func launchdSocket(name, path, group string) service.LaunchdSocket {
	return service.LaunchdSocket{Name: name, Path: path, Owner: "root", Group: group, Mode: 0o660, DirectoryMode: 0o711}
}
