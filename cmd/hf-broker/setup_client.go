package main

import (
	"io"

	bksetup "github.com/osolmaz/brokerkit/setup"
)

type setupClientOptions = bksetup.ClientOptions

func parseSetupClient(stderr io.Writer, args []string) (setupClientOptions, error) {
	opts, help, err := bksetup.ParseClient(stderr, args, bksetup.ClientDefaults{
		BrokerName: "hf-broker", EnvPrefix: "HF_BROKER", ClientName: "agent",
	})
	if help {
		return setupClientOptions{}, exitError{code: 0}
	}
	if err != nil {
		return setupClientOptions{}, exitError{code: 64, message: err.Error()}
	}
	return opts, nil
}

func runSetupClient(stdout io.Writer, opts setupClientOptions) error {
	_, err := bksetup.ConfigureClient(stdout, opts)
	return err
}
