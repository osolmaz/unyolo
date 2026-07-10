// Package setup provides reusable broker setup command primitives.
package setup

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/osolmaz/brokerkit/clientconfig"
)

// ClientDefaults configures the shared setup client command.
type ClientDefaults struct {
	BrokerName string
	EnvPrefix  string
	ClientName string
}

// ClientOptions is one parsed setup client request.
type ClientOptions struct {
	BrokerName string
	EnvPrefix  string
	ClientName string
	URL        string
	SecretFile string
	HomeDir    string
}

// ParseClient parses the broker-family setup client flags. Help is true when
// flag help was printed and no setup should run.
func ParseClient(stderr io.Writer, args []string, defaults ClientDefaults) (opts ClientOptions, help bool, err error) {
	opts = ClientOptions{
		BrokerName: defaults.BrokerName,
		EnvPrefix:  defaults.EnvPrefix,
		ClientName: defaults.ClientName,
	}
	var flagOutput strings.Builder
	fs := flag.NewFlagSet(defaults.BrokerName+" setup client", flag.ContinueOnError)
	fs.SetOutput(&flagOutput)
	fs.StringVar(&opts.ClientName, "client", opts.ClientName, "broker client name to read from the secrets file")
	fs.StringVar(&opts.URL, "url", "", "broker base URL")
	fs.StringVar(&opts.SecretFile, "secret-file", "", "file containing broker client secrets")
	fs.StringVar(&opts.HomeDir, "home-dir", "", "home directory that receives the broker client config")
	if parseErr := fs.Parse(args); parseErr != nil {
		if errors.Is(parseErr, flag.ErrHelp) {
			_, _ = io.Copy(stderr, strings.NewReader(flagOutput.String()))
			return ClientOptions{}, true, nil
		}
		return ClientOptions{}, false, errors.New("invalid setup client flags")
	}
	if fs.NArg() != 0 {
		return ClientOptions{}, false, errors.New("setup client does not accept positional arguments")
	}
	if opts.HomeDir == "" {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return ClientOptions{}, false, fmt.Errorf("resolve home directory: %w", homeErr)
		}
		opts.HomeDir = home
	}
	if err := opts.Validate(); err != nil {
		return ClientOptions{}, false, err
	}
	return opts, false, nil
}

// Validate validates one setup client request.
func (opts ClientOptions) Validate() error {
	if err := validateClientIdentity(opts); err != nil {
		return err
	}
	if err := clientconfig.ValidateURL(opts.URL); err != nil {
		return err
	}
	return validateClientLocations(opts)
}

func validateClientIdentity(opts ClientOptions) error {
	if strings.TrimSpace(opts.BrokerName) == "" || strings.TrimSpace(opts.EnvPrefix) == "" {
		return errors.New("broker name and environment prefix are required")
	}
	if err := clientconfig.ValidateClientName(opts.ClientName); err != nil {
		return fmt.Errorf("--client: %w", err)
	}
	return nil
}

func validateClientLocations(opts ClientOptions) error {
	if strings.TrimSpace(opts.SecretFile) == "" {
		return errors.New("--secret-file is required")
	}
	if strings.TrimSpace(opts.HomeDir) == "" {
		return errors.New("--home-dir must not be empty")
	}
	return nil
}

// ConfigureClient writes the client environment and prints only non-secret
// setup metadata.
func ConfigureClient(stdout io.Writer, opts ClientOptions) (string, error) {
	if err := opts.Validate(); err != nil {
		return "", err
	}
	secret, err := clientconfig.SecretFromFile(opts.SecretFile, opts.ClientName)
	if err != nil {
		return "", err
	}
	path, err := clientconfig.WriteForHomeOwner(clientconfig.Config{
		BrokerName: opts.BrokerName,
		EnvPrefix:  opts.EnvPrefix,
		URL:        opts.URL,
		Secret:     secret,
		HomeDir:    opts.HomeDir,
	})
	if err != nil {
		return "", err
	}
	_, err = fmt.Fprintf(stdout, "%s client config written\n  client: %s\n  file: %s\n  url: %s\n", opts.BrokerName, opts.ClientName, path, opts.URL)
	return path, err
}
