package gitclient

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
)

// RunCommand executes the provider-neutral <broker> git command family.
func RunCommand(ctx context.Context, provider Provider, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: git install|uninstall|status|doctor")
	}
	command := args[0]
	flags := flag.NewFlagSet(provider.BrokerName+" git "+command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	options := Options{}
	mode := string(ModeAll)
	jsonOutput := false
	flags.StringVar(&options.HomeDir, "home-dir", "", "home directory to configure")
	flags.StringVar(&mode, "mode", mode, "routing mode: all or push-only")
	flags.BoolVar(&options.Replace, "replace", false, "replace an existing BrokerKit-owned installation")
	flags.BoolVar(&jsonOutput, "json", false, "print machine-readable status")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("git command does not accept positional arguments")
	}
	options.Mode = Mode(mode)
	var status Status
	var err error
	switch command {
	case "install":
		status, err = Install(ctx, provider, options)
	case "uninstall":
		status, err = Uninstall(ctx, provider, options)
	case "status":
		status, err = Inspect(ctx, provider, options)
	case "doctor":
		status, err = Doctor(ctx, provider, options)
	default:
		return errors.New("usage: git install|uninstall|status|doctor")
	}
	if err != nil {
		return err
	}
	if jsonOutput {
		return json.NewEncoder(stdout).Encode(status)
	}
	if status.Installed {
		_, err = fmt.Fprintf(stdout, "%s Git routing ready\n  provider: %s\n  mode: %s\n  listener: %s\n", provider.BrokerName, status.Provider, status.Mode, status.Origin)
		return err
	}
	_, err = fmt.Fprintf(stdout, "%s Git routing is not installed\n", provider.BrokerName)
	return err
}

// ParseCredentialArgs parses git-credential-brokerkit's provider and action.
func ParseCredentialArgs(args []string) (string, string, error) {
	provider := ""
	action := ""
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--provider":
			index++
			if index >= len(args) || provider != "" {
				return "", "", errors.New("--provider requires one value")
			}
			provider = args[index]
		default:
			if strings.HasPrefix(args[index], "-") || action != "" {
				return "", "", errors.New("invalid credential-helper arguments")
			}
			action = args[index]
		}
	}
	if provider == "" || action == "" {
		return "", "", errors.New("provider and credential-helper action are required")
	}
	return provider, action, nil
}
