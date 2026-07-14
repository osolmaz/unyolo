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
}

func TestBuildSystemdActivationRejectsTCP(t *testing.T) {
	opts := DefaultSystemdOptions(SystemdDefaults{BrokerName: "test-broker", User: "test-broker", Group: "test-broker", Endpoint: "tcp://127.0.0.1:9000"})
	if _, err := BuildSystemdActivation(opts, "unix:///run/test/operator.sock", "test-broker.service"); err == nil {
		t.Fatal("TCP systemd endpoint was accepted")
	}
}
