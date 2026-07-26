package component

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/osolmaz/brokerkit/agent/client"
	"github.com/osolmaz/brokerkit/deployment/api"
	"github.com/osolmaz/brokerkit/internal/config/client"
)

// Probe runs one authenticated safe discovery through the normal agent config.
func Probe(ctx context.Context, args []string) error {
	if len(args) != 3 {
		return errors.New("setup-component-probe requires HOME BROKER ENV_PREFIX")
	}
	home, broker, prefix := args[0], args[1], args[2]
	if !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return errors.New("setup-component-probe home is invalid")
	}
	configured, err := clientconfig.Read(home, broker, prefix)
	if err != nil {
		return err
	}
	client, err := agentclient.New(agentclient.Options{Endpoint: configured.AgentEndpoint, Credential: configured.SharedSecret})
	if err != nil {
		return err
	}
	_, err = client.Discover(ctx)
	return err
}

func runClientProbe(ctx context.Context, agent api.AgentBinding, spec Client) error {
	resolved, err := user.Lookup(agent.UnixUser)
	if err != nil {
		return err
	}
	uid, err := strconv.ParseUint(resolved.Uid, 10, 32)
	if err != nil {
		return err
	}
	gid, err := strconv.ParseUint(resolved.Gid, 10, 32)
	if err != nil {
		return err
	}
	groupIDs, err := resolved.GroupIds()
	if err != nil {
		return err
	}
	groups := make([]uint32, 0, len(groupIDs))
	for _, value := range groupIDs {
		parsed, parseErr := strconv.ParseUint(value, 10, 32)
		if parseErr != nil {
			return parseErr
		}
		groups = append(groups, uint32(parsed))
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, executable, "setup-component-probe", agent.Home, spec.BrokerName, spec.EnvPrefix) // #nosec G204 -- fixed self-exec with validated profile fields.
	command.Env = []string{"HOME=" + agent.Home, "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{ // #nosec G115 -- ParseUint bounds both values to 32 bits.
		Uid: uint32(uid), Gid: uint32(gid), Groups: groups,
	}}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("real-agent client probe failed: %w", err)
	}
	if strings.TrimSpace(string(output)) != "ok" {
		return errors.New("real-agent client probe returned invalid output")
	}
	return nil
}
