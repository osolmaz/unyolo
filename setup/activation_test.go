package setup

import "testing"

func TestBuildSystemdActivation(t *testing.T) {
	opts := DefaultSystemdOptions(SystemdDefaults{BrokerName: "test-broker", User: "test-broker", Group: "test-broker", Endpoint: "unix:///run/test-broker/agent/broker.sock"})
	opts.AgentUser = "agent-user"
	opts.OperatorUser = "operator-user"
	got, err := BuildSystemdActivation(opts, "unix:///run/test-broker/operator/broker.sock", "test-broker.service")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Sockets) != 2 || got.Sockets[0].Unit.FileDescriptorName != "agent" || got.Sockets[1].Unit.FileDescriptorName != "operator" {
		t.Fatalf("activation = %+v", got)
	}
	if got.GroupMembers[opts.AgentAccessGroup][0] != opts.AgentUser || got.GroupMembers[opts.OperatorAccessGroup][0] != opts.OperatorUser {
		t.Fatalf("group members = %+v", got.GroupMembers)
	}
	if len(got.ActivationUnits) != 3 || got.ActivationUnits[2] != "test-broker.service" {
		t.Fatalf("activation units = %v", got.ActivationUnits)
	}
}

func TestBuildSystemdActivationRejectsTCP(t *testing.T) {
	opts := DefaultSystemdOptions(SystemdDefaults{BrokerName: "test-broker", User: "test-broker", Group: "test-broker", Endpoint: "tcp://127.0.0.1:9000"})
	if _, err := BuildSystemdActivation(opts, "unix:///run/test/operator.sock", "test-broker.service"); err == nil {
		t.Fatal("TCP systemd endpoint was accepted")
	}
}

func TestBuildLaunchdActivation(t *testing.T) {
	opts := SystemdOptions{BrokerName: "test-broker", User: "_test_broker", AgentUser: "bob", OperatorUser: "onur",
		AgentAccessGroup: "test-agent", OperatorAccessGroup: "test-operator",
		Endpoint: "unix:///var/run/brokerkit/test/agent/broker.sock"}
	got, err := BuildLaunchdActivation(opts, "unix:///var/run/brokerkit/test/operator/broker.sock")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Sockets) != 2 || got.Sockets[0].Name != "agent" || got.Sockets[1].Name != "operator" {
		t.Fatalf("BuildLaunchdActivation() sockets = %+v", got.Sockets)
	}
	if got.Sockets[0].Group != "test-agent" || got.Sockets[1].Group != "test-operator" {
		t.Fatalf("BuildLaunchdActivation() groups = %+v", got.Sockets)
	}
	if got.GroupMembers["test-agent"][0] != "bob" || got.GroupMembers["test-operator"][0] != "onur" {
		t.Fatalf("BuildLaunchdActivation() members = %+v", got.GroupMembers)
	}
}

func TestBuildLaunchdActivationRejectsTCP(t *testing.T) {
	opts := SystemdOptions{BrokerName: "test", User: "test", Endpoint: "tcp://127.0.0.1:30000"}
	if _, err := BuildLaunchdActivation(opts, "unix:///var/run/test/operator.sock"); err == nil {
		t.Fatal("BuildLaunchdActivation(tcp) error = nil")
	}
}
