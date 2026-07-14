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

// BuildSystemdActivation builds permission-separated agent and operator Unix
// socket activation. The client-facing endpoints remain concrete Unix URIs;
// the service consumes the descriptors as activation://agent and
// activation://operator.
func BuildSystemdActivation(opts SystemdOptions, operatorEndpoint, serviceUnit string) (SystemdActivation, error) {
	opts = activationDefaults(opts)
	agent, err := endpoint.Parse(opts.Endpoint, endpoint.ParseOptions{})
	if err != nil {
		return SystemdActivation{}, fmt.Errorf("agent endpoint: %w", err)
	}
	operator, err := endpoint.Parse(operatorEndpoint, endpoint.ParseOptions{})
	if err != nil {
		return SystemdActivation{}, fmt.Errorf("operator endpoint: %w", err)
	}
	if agent.Scheme() != endpoint.SchemeUnix || operator.Scheme() != endpoint.SchemeUnix {
		return SystemdActivation{}, errors.New("systemd setup requires concrete Unix client endpoints")
	}
	if agent.Path() == operator.Path() {
		return SystemdActivation{}, errors.New("agent and operator socket paths must differ")
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
		ActivationUnits: []string{sockets[0].UnitName, sockets[1].UnitName},
	}, nil
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
		SocketUser: "root", SocketGroup: group, SocketMode: 0o660, DirectoryMode: 0o750,
	}}
}
