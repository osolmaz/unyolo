package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"

	pairingservice "github.com/osolmaz/unyolo/internal/pairing"
	"github.com/osolmaz/unyolo/transport/endpoint"
	serverhttp "github.com/osolmaz/unyolo/transport/http/server"
)

var version = "dev"

type options struct {
	stateDirectory  string
	publicEndpoint  string
	controlEndpoint string
	certificateFile string
	privateKeyFile  string
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 1 && args[0] == "version" {
		_, err := fmt.Fprintln(stdout, version)
		return err
	}
	flags := flag.NewFlagSet("unyolo-pairing", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var value options
	flags.StringVar(&value.stateDirectory, "state", "", "private pairing state directory")
	flags.StringVar(&value.publicEndpoint, "public-endpoint", "", "public TLS endpoint")
	flags.StringVar(&value.controlEndpoint, "control-endpoint", "", "protected local control endpoint")
	flags.StringVar(&value.certificateFile, "tls-cert-file", "", "TLS server certificate")
	flags.StringVar(&value.privateKeyFile, "tls-key-file", "", "TLS server private key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || value.stateDirectory == "" || value.publicEndpoint == "" || value.controlEndpoint == "" {
		return errors.New("--state, --public-endpoint, and --control-endpoint are required")
	}
	publicEndpoint, err := endpoint.Parse(value.publicEndpoint, endpoint.ParseOptions{AllowNetworkTLS: true})
	if err != nil || publicEndpoint.Scheme() != endpoint.SchemeTLS {
		return errors.New("public pairing endpoint must use TLS")
	}
	controlEndpoint, err := endpoint.Parse(value.controlEndpoint, endpoint.ParseOptions{})
	if err != nil || controlEndpoint.Scheme() != endpoint.SchemeUnix && controlEndpoint.Scheme() != endpoint.SchemeActivation {
		return errors.New("pairing control endpoint must be a local Unix socket")
	}
	tlsConfig, err := endpoint.ServerTLSConfig(value.certificateFile, value.privateKeyFile)
	if err != nil {
		return err
	}
	listeners, err := endpoint.ListenSet([]endpoint.Named{{Name: "public", Endpoint: publicEndpoint}, {Name: "control", Endpoint: controlEndpoint}}, endpoint.ListenOptions{TLSConfig: tlsConfig})
	if err != nil {
		return err
	}
	store := &pairingservice.Store{Directory: value.stateDirectory}
	return serve(ctx, listeners, store, stdout)
}

func serve(ctx context.Context, listeners map[string]net.Listener, store *pairingservice.Store, stdout io.Writer) error {
	publicServer, err := serverhttp.New(pairingservice.PublicHandler(store), serverhttp.ProfileOperator)
	if err != nil {
		_ = endpoint.CloseSet(listeners)
		return err
	}
	controlServer, err := serverhttp.New(pairingservice.ControlHandler(store), serverhttp.ProfileOperator)
	if err != nil {
		_ = endpoint.CloseSet(listeners)
		return err
	}
	_, _ = fmt.Fprintln(stdout, "unyolo pairing service ready")
	return serverhttp.Serve(ctx, []serverhttp.Binding{{Server: publicServer, Listener: listeners["public"]}, {Server: controlServer, Listener: listeners["control"]}})
}
