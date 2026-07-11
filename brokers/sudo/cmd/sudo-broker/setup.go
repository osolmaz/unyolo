package main

import (
	"context"
	"errors"
	"io"

	bksetup "github.com/osolmaz/brokerkit/setup"
)

const setupUsage = `usage:
  sudo-broker setup systemd --policy-file FILE --catalog-file FILE [flags]
  sudo-broker setup client --client NAME --url URL --secret-file FILE [--home-dir DIR]`

func runSetup(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New(setupUsage)
	}
	switch args[0] {
	case "client":
		opts, help, err := bksetup.ParseClient(stderr, args[1:], bksetup.ClientDefaults{
			BrokerName: "sudo-broker", EnvPrefix: "SUDO_BROKER", ClientName: "bob",
		})
		if err != nil || help {
			return err
		}
		_, err = bksetup.ConfigureClient(stdout, opts)
		return err
	case "systemd":
		return runSetupSystemd(ctx, args[1:], stdout, stderr)
	default:
		return errors.New(setupUsage)
	}
}
