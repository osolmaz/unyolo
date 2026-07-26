package identity

import (
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
	_, err := inspector.InspectDeployment(deployment)
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
	accounts, err := inspector.InspectDeployment(deployment)
	if err != nil {
		t.Fatal(err)
	}
	if accounts["agent:agent"].UID != 1001 || accounts["operator:operator"].UID != 1002 {
		t.Fatalf("accounts = %#v", accounts)
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
		LookupShell: func(string) (string, error) { return "/bin/false", nil },
	}
}
