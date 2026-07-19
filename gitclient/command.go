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
	command, options, jsonOutput, err := parseCommandOptions(provider, args, stderr)
	if err != nil {
		return err
	}
	status, err := executeCommand(ctx, provider, command, options)
	if err != nil {
		return err
	}
	return writeCommandStatus(stdout, provider, status, jsonOutput)
}

func parseCommandOptions(provider Provider, args []string, stderr io.Writer) (string, Options, bool, error) {
	command := args[0]
	flags := flag.NewFlagSet(provider.BrokerName+" git "+command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	options := Options{}
	jsonOutput := false
	flags.StringVar(&options.HomeDir, "home-dir", "", "home directory to configure")
	flags.BoolVar(&options.Replace, "replace", false, "replace an existing BrokerKit-owned installation")
	flags.BoolVar(&jsonOutput, "json", false, "print machine-readable status")
	if err := flags.Parse(args[1:]); err != nil {
		return "", Options{}, false, err
	}
	if flags.NArg() != 0 {
		return "", Options{}, false, errors.New("git command does not accept positional arguments")
	}
	return command, options, jsonOutput, nil
}

func executeCommand(ctx context.Context, provider Provider, command string, options Options) (Status, error) {
	switch command {
	case "install":
		return Install(ctx, provider, options)
	case "uninstall":
		return Uninstall(ctx, provider, options)
	case "status":
		return Inspect(ctx, provider, options)
	case "doctor":
		return Doctor(ctx, provider, options)
	default:
		return Status{}, errors.New("usage: git install|uninstall|status|doctor")
	}
}

func writeCommandStatus(stdout io.Writer, provider Provider, status Status, jsonOutput bool) error {
	if jsonOutput {
		return json.NewEncoder(stdout).Encode(status)
	}
	if status.Installed {
		_, err := fmt.Fprintf(stdout, "%s Git routing ready\n  provider: %s\n  mode: %s\n  listener: %s\n", provider.BrokerName, status.Provider, status.Mode, status.Origin)
		return err
	}
	_, err := fmt.Fprintf(stdout, "%s Git routing is not installed\n", provider.BrokerName)
	return err
}

// ParseCredentialArgs parses git-credential-brokerkit's provider and action.
func ParseCredentialArgs(args []string) (string, string, error) {
	provider := ""
	action := ""
	for len(args) > 0 {
		consumed, err := consumeCredentialArg(args, &provider, &action)
		if err != nil {
			return "", "", err
		}
		args = args[consumed:]
	}
	if provider == "" || action == "" {
		return "", "", errors.New("provider and credential-helper action are required")
	}
	return provider, action, nil
}

func consumeCredentialArg(args []string, provider, action *string) (int, error) {
	if args[0] == "--provider" {
		if len(args) < 2 || *provider != "" {
			return 0, errors.New("--provider requires one value")
		}
		*provider = args[1]
		return 2, nil
	}
	if strings.HasPrefix(args[0], "-") || *action != "" {
		return 0, errors.New("invalid credential-helper arguments")
	}
	*action = args[0]
	return 1, nil
}
