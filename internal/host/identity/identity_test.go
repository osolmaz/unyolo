package identity

import (
	"context"
	"errors"
	"os/user"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/deployment/profile"
)

func TestInspectDeploymentRejectsRootEquivalentAgent(t *testing.T) {
	inspector := fakeInspector(map[string]*user.User{
		"agent":    {Username: "agent", Uid: "1001", Gid: "1001", HomeDir: "/home/agent"},
		"operator": {Username: "operator", Uid: "1002", Gid: "1002", HomeDir: "/home/operator"},
	}, map[string][]string{"agent": {"1001", "27"}, "operator": {"1002"}})
	deployment := profile.Deployment{
		Agents:    []profile.Agent{{ID: "agent", UnixUser: "agent", AccountMode: "existing", Home: "/home/agent", Shell: "/bin/false"}},
		Operators: []profile.Operator{{ID: "operator", UnixUser: "operator"}},
	}
	_, err := inspector.InspectDeployment(context.Background(), deployment)
	if err == nil || !strings.Contains(err.Error(), "root-equivalent") {
		t.Fatalf("InspectDeployment() error = %v", err)
	}
}

func TestInspectDeploymentAcceptsSeparatedAccounts(t *testing.T) {
	inspector := fakeInspector(map[string]*user.User{
		"agent":    {Username: "agent", Uid: "1001", Gid: "1001", HomeDir: "/home/agent"},
		"operator": {Username: "operator", Uid: "1002", Gid: "1002", HomeDir: "/home/operator"},
	}, map[string][]string{"agent": {"1001"}, "operator": {"1002"}})
	deployment := profile.Deployment{
		Agents:    []profile.Agent{{ID: "agent", UnixUser: "agent", AccountMode: "existing", Home: "/home/agent", Shell: "/bin/false"}},
		Operators: []profile.Operator{{ID: "operator", UnixUser: "operator"}},
	}
	accounts, err := inspector.InspectDeployment(context.Background(), deployment)
	if err != nil {
		t.Fatal(err)
	}
	if accounts["agent:agent"].UID != 1001 || accounts["operator:operator"].UID != 1002 {
		t.Fatalf("accounts = %#v", accounts)
	}
}

func TestInspectDeploymentFailureModes(t *testing.T) {
	baseUsers := map[string]*user.User{
		"agent":    {Username: "agent", Uid: "1001", Gid: "1001", HomeDir: "/home/agent"},
		"operator": {Username: "operator", Uid: "1002", Gid: "1002", HomeDir: "/home/operator"},
	}
	baseGroups := map[string][]string{"agent": {"1001"}, "operator": {"1002"}}
	base := profile.Deployment{
		Agents:    []profile.Agent{{ID: "agent", UnixUser: "agent", AccountMode: "existing", Home: "/home/agent", Shell: "/bin/false"}},
		Operators: []profile.Operator{{ID: "operator", UnixUser: "operator"}},
	}
	tests := []struct {
		name    string
		users   map[string]*user.User
		groups  map[string][]string
		prepare func(*profile.Deployment)
	}{
		{"missing existing agent", baseUsers, baseGroups, func(value *profile.Deployment) { value.Agents[0].UnixUser = "missing" }},
		{"home mismatch", baseUsers, baseGroups, func(value *profile.Deployment) { value.Agents[0].Home = "/wrong" }},
		{"duplicate agent UID", baseUsers, baseGroups, func(value *profile.Deployment) {
			value.Agents = append(value.Agents, profile.Agent{ID: "two", UnixUser: "agent", AccountMode: "existing", Home: "/home/agent", Shell: "/bin/false"})
		}},
		{"operator shares UID", map[string]*user.User{"agent": baseUsers["agent"], "operator": {Username: "operator", Uid: "1001", Gid: "1002", HomeDir: "/home/operator"}}, baseGroups, func(*profile.Deployment) {}},
		{"root operator", map[string]*user.User{"agent": baseUsers["agent"], "operator": {Username: "operator", Uid: "0", Gid: "0", HomeDir: "/root"}}, map[string][]string{"agent": {"1001"}, "operator": {"0"}}, func(*profile.Deployment) {}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deployment := base
			deployment.Agents = append([]profile.Agent(nil), base.Agents...)
			test.prepare(&deployment)
			if _, err := fakeInspector(test.users, test.groups).InspectDeployment(context.Background(), deployment); err == nil {
				t.Fatal("unsafe identity deployment was accepted")
			}
		})
	}
	managed := base
	managed.Agents[0].UnixUser = "managed-agent"
	managed.Agents[0].AccountMode = "managed"
	accounts, err := fakeInspector(baseUsers, baseGroups).InspectDeployment(context.Background(), managed)
	if err != nil || !accounts["agent:agent"].Missing {
		t.Fatalf("managed missing account = %#v, %v", accounts, err)
	}
}

func TestLookupCurrentShell(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	shell, err := lookupShell(context.Background(), current.Username)
	if err != nil || shell == "" {
		t.Fatalf("lookupShell() = %q, %v", shell, err)
	}
}

func TestSafeManagedCommand(t *testing.T) {
	valid := profile.Agent{UnixUser: "brokerkit-agent", AccountMode: "managed", Home: "/var/lib/brokerkit-agent", Shell: "/usr/sbin/nologin"}
	command, err := SafeManagedCommand(valid)
	if err != nil {
		t.Fatal(err)
	}
	if len(command) < 2 || command[0] != "useradd" || command[len(command)-1] != valid.UnixUser {
		t.Fatalf("command = %v", command)
	}
	for _, invalid := range []profile.Agent{
		{UnixUser: "bad user", AccountMode: "managed", Home: valid.Home, Shell: valid.Shell},
		{UnixUser: valid.UnixUser, AccountMode: "existing", Home: valid.Home, Shell: valid.Shell},
		{UnixUser: valid.UnixUser, AccountMode: "managed", Home: "relative", Shell: valid.Shell},
		{UnixUser: valid.UnixUser, AccountMode: "managed", Home: valid.Home, Shell: "/bin/bash"},
	} {
		if _, err := SafeManagedCommand(invalid); err == nil {
			t.Fatalf("unsafe agent was accepted: %#v", invalid)
		}
	}
}

func fakeInspector(users map[string]*user.User, groupIDs map[string][]string) Inspector {
	groups := map[string]string{"1001": "agent", "1002": "operator", "27": "sudo"}
	return Inspector{
		LookupUser: func(name string) (*user.User, error) {
			value := users[name]
			if value == nil {
				return nil, user.UnknownUserError(name)
			}
			return value, nil
		},
		LookupGroupIDs: func(value *user.User) ([]string, error) { return groupIDs[value.Username], nil },
		LookupGroupID: func(id string) (*user.Group, error) {
			name := groups[id]
			if name == "" {
				return nil, errors.New("unknown group")
			}
			return &user.Group{Name: name, Gid: id}, nil
		},
		LookupShell: func(context.Context, string) (string, error) { return "/bin/false", nil },
	}
}
