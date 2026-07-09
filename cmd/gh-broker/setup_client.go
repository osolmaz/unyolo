package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/osolmaz/brokerkit/clientconfig"
)

const setupUsage = "usage: gh-broker setup client --client <name> --url <url> --secret-file <path> [--home-dir <path>]"

type setupClientOptions struct {
	ClientName string
	URL        string
	SecretFile string
	HomeDir    string
}

func runSetup(stdout io.Writer, stderr io.Writer, args []string) error {
	if len(args) == 0 || args[0] != "client" {
		return errors.New(setupUsage)
	}
	opts, err := parseSetupClient(stderr, args[1:])
	if err != nil {
		return err
	}
	return runSetupClient(stdout, opts)
}

func parseSetupClient(stderr io.Writer, args []string) (setupClientOptions, error) {
	opts := setupClientOptions{ClientName: "bob"}
	fs, flagOutput := setupClientFlagSet(&opts)
	if err := fs.Parse(args); err != nil {
		return setupClientOptions{}, handleSetupClientFlagError(stderr, flagOutput.String(), err)
	}
	if fs.NArg() != 0 {
		return setupClientOptions{}, errors.New("setup client does not accept positional arguments")
	}
	if err := defaultSetupClientHome(&opts); err != nil {
		return setupClientOptions{}, err
	}
	return opts, validateSetupClientOptions(opts)
}

func setupClientFlagSet(opts *setupClientOptions) (*flag.FlagSet, *strings.Builder) {
	var flagOutput strings.Builder
	fs := flag.NewFlagSet("gh-broker setup client", flag.ContinueOnError)
	fs.SetOutput(&flagOutput)
	fs.StringVar(&opts.ClientName, "client", opts.ClientName, "broker client name to read from the secrets file")
	fs.StringVar(&opts.URL, "url", "", "broker base URL")
	fs.StringVar(&opts.SecretFile, "secret-file", "", "file containing broker client secrets")
	fs.StringVar(&opts.HomeDir, "home-dir", "", "home directory that receives .config/gh-broker/client.env")
	return fs, &flagOutput
}

func handleSetupClientFlagError(stderr io.Writer, flagOutput string, err error) error {
	if errors.Is(err, flag.ErrHelp) {
		_, _ = io.Copy(stderr, strings.NewReader(flagOutput))
		return nil
	}
	return errors.New("invalid setup client flags")
}

func defaultSetupClientHome(opts *setupClientOptions) error {
	if opts.HomeDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("resolve home directory: %w", err)
		}
		opts.HomeDir = home
	}
	return nil
}

func validateSetupClientOptions(opts setupClientOptions) error {
	if opts.ClientName == "" {
		return errors.New("--client must not be empty")
	}
	if opts.URL == "" {
		return errors.New("--url is required")
	}
	if opts.SecretFile == "" {
		return errors.New("--secret-file is required")
	}
	if opts.HomeDir == "" {
		return errors.New("--home-dir must not be empty")
	}
	return nil
}

func runSetupClient(stdout io.Writer, opts setupClientOptions) error {
	secret, err := clientconfig.SecretFromFile(opts.SecretFile, opts.ClientName)
	if err != nil {
		return err
	}
	path, err := clientconfig.Write(clientconfig.Config{
		BrokerName: "gh-broker",
		EnvPrefix:  "GH_BROKER",
		URL:        opts.URL,
		Secret:     secret,
		HomeDir:    opts.HomeDir,
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "gh-broker client config written\n  client: %s\n  file: %s\n  url: %s\n", opts.ClientName, path, opts.URL)
	return err
}
