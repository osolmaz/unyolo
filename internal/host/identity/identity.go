// Package identity inspects and plans safe unYOLO agent identities.
package identity

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/osolmaz/unyolo/deployment/profile"
)

var (
	rootEquivalentGroups = []string{"sudo", "wheel", "docker", "lxd", "incus"}
	managedNamePattern   = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

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
	LookupShell    func(context.Context, string) (string, error)
}

// InspectDeployment resolves every agent and operator and enforces separation.
//
//nolint:cyclop // Agent and operator uniqueness and root-equivalence checks require the complete identity set.
func (inspector Inspector) InspectDeployment(ctx context.Context, deployment profile.Deployment) (map[string]Account, error) {
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
	reducedUIDs := map[int]bool{}
	for _, agent := range deployment.Agents {
		if agent.Target.Kind != "local_account" {
			continue
		}
		account, err := inspector.inspect(ctx, agent.Target.UnixUser)
		if err != nil {
			var unknown user.UnknownUserError
			if agent.Target.AccountMode == "managed" && errors.As(err, &unknown) {
				result["agent:"+agent.ID] = Account{Name: agent.Target.UnixUser, Home: agent.Target.Home, Shell: agent.Target.Shell, Missing: true}
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
		reducedUIDs[account.UID] = agent.Target.Isolation == "reduced"
		result["agent:"+agent.ID] = account
	}
	for _, operator := range deployment.Operators {
		account, err := inspector.inspect(ctx, operator.UnixUser)
		if err != nil {
			var unknown user.UnknownUserError
			if operator.Managed() && errors.As(err, &unknown) {
				result["operator:"+operator.ID] = Account{Name: operator.UnixUser, Home: operator.Home, Shell: operator.Shell, Missing: true}
				continue
			}
			return nil, fmt.Errorf("inspect operator %q: %w", operator.ID, err)
		}
		if account.UID == 0 {
			return nil, fmt.Errorf("operator %q must not bind root directly", operator.ID)
		}
		if err := validateManagedOperator(account, operator); err != nil {
			return nil, fmt.Errorf("operator %q: %w", operator.ID, err)
		}
		if previous := usedUIDs[account.UID]; previous != "" && !reducedUIDs[account.UID] {
			return nil, fmt.Errorf("operator %q shares UID with %s", operator.ID, previous)
		}
		usedUIDs[account.UID] = "operator " + operator.ID
		result["operator:"+operator.ID] = account
	}
	return result, nil
}

func (inspector Inspector) inspect(ctx context.Context, name string) (Account, error) {
	resolved, err := inspector.LookupUser(name)
	if err != nil {
		return Account{}, err
	}
	uid, err := strconv.Atoi(resolved.Uid)
	if err != nil {
		return Account{}, errors.New("unix UID is invalid")
	}
	gid, err := strconv.Atoi(resolved.Gid)
	if err != nil {
		return Account{}, errors.New("unix GID is invalid")
	}
	shell, err := inspector.LookupShell(ctx, name)
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

func lookupShell(ctx context.Context, name string) (string, error) {
	if runtime.GOOS == "darwin" {
		output, err := exec.CommandContext(ctx, "dscl", ".", "-read", "/Users/"+name, "UserShell").Output() // #nosec G204 -- validated profile user is one argument to a fixed command.
		if err != nil {
			return "", err
		}
		_, shell, found := strings.Cut(strings.TrimSpace(string(output)), ":")
		if !found || !filepath.IsAbs(strings.TrimSpace(shell)) {
			return "", errors.New("login shell is invalid")
		}
		return strings.TrimSpace(shell), nil
	}
	output, err := exec.CommandContext(ctx, "getent", "passwd", name).Output() // #nosec G204 -- validated profile user is one argument to a fixed command.
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
	if desired.Target.Isolation != "reduced" {
		for _, group := range rootEquivalentGroups {
			if slices.Contains(account.Groups, group) {
				return fmt.Errorf("agent belongs to root-equivalent group %q", group)
			}
		}
	}
	if filepath.Clean(account.Home) != desired.Target.Home {
		return fmt.Errorf("home mismatch: found %q", account.Home)
	}
	if account.Shell != "" && filepath.Clean(account.Shell) != desired.Target.Shell {
		return fmt.Errorf("shell mismatch: found %q", account.Shell)
	}
	return nil
}

// validateManagedOperator checks that an existing account still matches a
// managed operator. A managed operator is a service account: it has no
// root-equivalent group, and its home and shell match the deployment.
func validateManagedOperator(account Account, desired profile.Operator) error {
	if !desired.Managed() {
		return nil
	}
	for _, group := range rootEquivalentGroups {
		if slices.Contains(account.Groups, group) {
			return fmt.Errorf("managed operator belongs to root-equivalent group %q", group)
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

// Managed is one noninteractive account that unYOLO creates for a managed
// agent or a managed operator.
type Managed struct {
	// Key is the account key in the inspected identity map.
	Key string
	// Kind is the transaction step kind that creates the account.
	Kind     string
	UnixUser string
	Home     string
	Shell    string
}

// ManagedAccounts returns every managed agent and operator account of a
// deployment, agents first.
func ManagedAccounts(deployment profile.Deployment) []Managed {
	var result []Managed
	for _, agent := range deployment.Agents {
		if agent.Target.Kind == "local_account" && agent.Target.AccountMode == "managed" {
			result = append(result, Managed{
				Key: "agent:" + agent.ID, Kind: "identity:" + agent.ID,
				UnixUser: agent.Target.UnixUser, Home: agent.Target.Home, Shell: agent.Target.Shell,
			})
		}
	}
	for _, operator := range deployment.Operators {
		if operator.Managed() {
			result = append(result, Managed{
				Key: "operator:" + operator.ID, Kind: "identity:operator." + operator.ID,
				UnixUser: operator.UnixUser, Home: operator.Home, Shell: operator.Shell,
			})
		}
	}
	return result
}

// Command returns one fixed Linux account-creation argv.
func (managed Managed) Command() ([]string, error) {
	if !managedNamePattern.MatchString(managed.UnixUser) || !filepath.IsAbs(managed.Home) || filepath.Clean(managed.Home) != managed.Home ||
		managed.Home == "/" || managed.Home == "/root" || !filepath.IsAbs(managed.Shell) ||
		!slices.Contains([]string{"nologin", "false"}, filepath.Base(managed.Shell)) {
		return nil, errors.New("managed account fields are unsafe")
	}
	return []string{"useradd", "--system", "--create-home", "--home-dir", managed.Home, "--shell", managed.Shell, managed.UnixUser}, nil
}
