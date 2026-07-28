package main

import (
	"io"

	unyolosetup "github.com/osolmaz/unyolo/internal/host/setup"
)

type setupClientOptions = unyolosetup.ClientOptions

func parseSetupClient(stderr io.Writer, args []string) (setupClientOptions, error) {
	opts, help, err := unyolosetup.ParseClient(stderr, args, unyolosetup.ClientDefaults{
		BrokerName: "hf-broker", EnvPrefix: "HF_BROKER",
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
	_, err := unyolosetup.ConfigureClient(stdout, opts)
	return err
}
