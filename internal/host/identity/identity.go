// Package identity inspects and plans safe BrokerKit agent identities.
package identity

import (
	"errors"
	"fmt"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/osolmaz/brokerkit/deployment/profile"
)

var rootEquivalentGroups = []string{"sudo", "wheel", "docker", "lxd", "incus"}

// Account is the resolved nonsecret Unix identity state.
type Account struct {
	Name    string   `json:"name"`
	UID     int      `json:"uid"`
	GID     int      `json:"gid"`
	Home    string   `json:"home"`
	Shell   string   `json:"shell"`
	Groups  []string `json:"groups"`
	Missing bool     `json:"missing,omitempty"`
}

// Inspector abstracts NSS for deterministic tests.
type Inspector struct {
	LookupUser     func(string) (*user.User, error)
	LookupGroupID  func(string) (*user.Group, error)
	LookupGroupIDs func(*user.User) ([]string, error)
	LookupShell    func(string) (string, error)
}

// InspectDeployment resolves every agent and operator and enforces separation.
func (inspector Inspector) InspectDeployment(deployment profile.Deployment) (map[string]Account, error) {
	if inspector.LookupUser == nil {
		inspector.LookupUser = user.Lookup
	}
	if inspector.LookupGroupID == nil {
		inspector.LookupGroupID = user.LookupGroupId
	}
	if inspector.LookupGroupIDs == nil {
		inspector.LookupGroupIDs = func(value *user.User) ([]string, error) { return value.GroupIds() }
	}
	if inspector.LookupShell == nil {
		inspector.LookupShell = lookupShell
	}
	result := map[string]Account{}
	usedUIDs := map[int]string{}
	for _, agent := range deployment.Agents {
		account, err := inspector.inspect(agent.UnixUser)
		if err != nil {
			var unknown user.UnknownUserError
			if agent.AccountMode == "managed" && errors.As(err, &unknown) {
				result["agent:"+agent.ID] = Account{Name: agent.UnixUser, Home: agent.Home, Shell: agent.Shell, Missing: true}
				continue
			}
			return nil, fmt.Errorf("inspect agent %q: %w", agent.ID, err)
		}
		if err := validateAgent(account, agent); err != nil {
			return nil, fmt.Errorf("agent %q: %w", agent.ID, err)
		}
		if previous := usedUIDs[account.UID]; previous != "" {
			return nil, fmt.Errorf("agent %q shares UID with %s", agent.ID, previous)
		}
		usedUIDs[account.UID] = "agent " + agent.ID
		result["agent:"+agent.ID] = account
	}
	for _, operator := range deployment.Operators {
		account, err := inspector.inspect(operator.UnixUser)
		if err != nil {
			return nil, fmt.Errorf("inspect operator %q: %w", operator.ID, err)
		}
		if account.UID == 0 {
			return nil, fmt.Errorf("operator %q must not bind root directly", operator.ID)
		}
		if previous := usedUIDs[account.UID]; previous != "" {
			return nil, fmt.Errorf("operator %q shares UID with %s", operator.ID, previous)
		}
		usedUIDs[account.UID] = "operator " + operator.ID
		result["operator:"+operator.ID] = account
	}
	return result, nil
}

func (inspector Inspector) inspect(name string) (Account, error) {
	resolved, err := inspector.LookupUser(name)
	if err != nil {
		return Account{}, err
	}
	uid, err := strconv.Atoi(resolved.Uid)
	if err != nil {
		return Account{}, errors.New("Unix UID is invalid")
	}
	gid, err := strconv.Atoi(resolved.Gid)
	if err != nil {
		return Account{}, errors.New("Unix GID is invalid")
	}
	shell, err := inspector.LookupShell(name)
	if err != nil {
		return Account{}, fmt.Errorf("resolve login shell: %w", err)
	}
	groupIDs, err := inspector.LookupGroupIDs(resolved)
	if err != nil {
		return Account{}, fmt.Errorf("resolve supplementary groups: %w", err)
	}
	groups := make([]string, 0, len(groupIDs))
	for _, groupID := range groupIDs {
		group, lookupErr := inspector.LookupGroupID(groupID)
		if lookupErr != nil {
			return Account{}, fmt.Errorf("resolve group %q: %w", groupID, lookupErr)
		}
		groups = append(groups, group.Name)
	}
	slices.Sort(groups)
	return Account{Name: name, UID: uid, GID: gid, Home: resolved.HomeDir, Shell: shell, Groups: groups}, nil
}

func lookupShell(name string) (string, error) {
	if runtime.GOOS == "darwin" {
		output, err := exec.Command("dscl", ".", "-read", "/Users/"+name, "UserShell").Output() // #nosec G204 -- validated profile user is one argument to a fixed command.
		if err != nil {
			return "", err
		}
		_, shell, found := strings.Cut(strings.TrimSpace(string(output)), ":")
		if !found || !filepath.IsAbs(strings.TrimSpace(shell)) {
			return "", errors.New("login shell is invalid")
		}
		return strings.TrimSpace(shell), nil
	}
	output, err := exec.Command("getent", "passwd", name).Output() // #nosec G204 -- validated profile user is one argument to a fixed command.
	if err != nil {
		return "", err
	}
	parts := strings.Split(strings.TrimSpace(string(output)), ":")
	if len(parts) != 7 || !filepath.IsAbs(parts[6]) {
		return "", errors.New("login shell is invalid")
	}
	return parts[6], nil
}

func validateAgent(account Account, desired profile.Agent) error {
	if account.UID == 0 {
		return errors.New("agent must not be root")
	}
	for _, group := range rootEquivalentGroups {
		if slices.Contains(account.Groups, group) {
			return fmt.Errorf("agent belongs to root-equivalent group %q", group)
		}
	}
	if filepath.Clean(account.Home) != desired.Home {
		return fmt.Errorf("home mismatch: found %q", account.Home)
	}
	if account.Shell != "" && filepath.Clean(account.Shell) != desired.Shell {
		return fmt.Errorf("shell mismatch: found %q", account.Shell)
	}
	return nil
}

// SafeManagedCommand returns one fixed Linux account-creation argv.
func SafeManagedCommand(agent profile.Agent) ([]string, error) {
	if agent.AccountMode != "managed" {
		return nil, errors.New("account is not managed")
	}
	if !filepath.IsAbs(agent.Home) || !filepath.IsAbs(agent.Shell) || strings.ContainsAny(agent.UnixUser, "\x00\r\n") {
		return nil, errors.New("managed account fields are unsafe")
	}
	return []string{"useradd", "--system", "--create-home", "--home-dir", agent.Home, "--shell", agent.Shell, agent.UnixUser}, nil
}
