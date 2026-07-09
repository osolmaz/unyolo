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

type setupClientOptions struct {
	ClientName string
	URL        string
	SecretFile string
	HomeDir    string
}

func parseSetupClient(stderr io.Writer, args []string) (setupClientOptions, error) {
	opts := setupClientOptions{ClientName: "agent"}
	var flagOutput strings.Builder
	fs := flag.NewFlagSet("hf-broker setup client", flag.ContinueOnError)
	fs.SetOutput(&flagOutput)
	fs.StringVar(&opts.ClientName, "client", opts.ClientName, "broker client name to read from the secrets file")
	fs.StringVar(&opts.URL, "url", "", "broker base URL")
	fs.StringVar(&opts.SecretFile, "secret-file", "", "file containing broker client secrets")
	fs.StringVar(&opts.HomeDir, "home-dir", "", "home directory that receives .config/hf-broker/client.env")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.Copy(stderr, strings.NewReader(flagOutput.String()))
			return setupClientOptions{}, exitError{code: 0}
		}
		return setupClientOptions{}, exitError{code: 64, message: "invalid setup client flags"}
	}
	if fs.NArg() != 0 {
		return setupClientOptions{}, exitError{code: 64, message: "setup client does not accept positional arguments"}
	}
	if opts.HomeDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return setupClientOptions{}, fmt.Errorf("resolve home directory: %w", err)
		}
		opts.HomeDir = home
	}
	return opts, validateSetupClientOptions(opts)
}

func validateSetupClientOptions(opts setupClientOptions) error {
	if opts.ClientName == "" {
		return exitError{code: 64, message: "--client must not be empty"}
	}
	if opts.URL == "" {
		return exitError{code: 64, message: "--url is required"}
	}
	if opts.SecretFile == "" {
		return exitError{code: 64, message: "--secret-file is required"}
	}
	if opts.HomeDir == "" {
		return exitError{code: 64, message: "--home-dir must not be empty"}
	}
	return nil
}

func runSetupClient(stdout io.Writer, opts setupClientOptions) error {
	secret, err := clientconfig.SecretFromFile(opts.SecretFile, opts.ClientName)
	if err != nil {
		return err
	}
	path, err := clientconfig.Write(clientconfig.Config{
		BrokerName: "hf-broker",
		EnvPrefix:  "HF_BROKER",
		URL:        opts.URL,
		Secret:     secret,
		HomeDir:    opts.HomeDir,
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "hf-broker client config written\n  client: %s\n  file: %s\n  url: %s\n", opts.ClientName, path, opts.URL)
	return err
}
