package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/osolmaz/brokerkit/internal/buildinfo"
	"github.com/osolmaz/brokerkit/internal/host/bundle"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 1 && (args[0] == "version" || args[0] == "--version") {
		_, err := fmt.Fprintln(stdout, version)
		return err
	}
	if len(args) < 2 || args[0] != "system" {
		return errors.New("usage: brokerkit system <plan|install|upgrade|status|doctor|rollback>")
	}
	buildinfo.Version = version
	switch args[1] {
	case "plan", "install", "upgrade":
		return runActivation(ctx, args[1], args[2:], stdout, stderr)
	case "status", "doctor":
		return runStatus(ctx, args[1], args[2:], stdout, stderr)
	case "rollback":
		return runRollback(ctx, args[2:], stdout, stderr)
	default:
		return errors.New("usage: brokerkit system <plan|install|upgrade|status|doctor|rollback>")
	}
}

type hostFlags struct {
	root    string
	state   string
	json    bool
	manager bundle.ServiceManager
}

func bindHostFlags(flags *flag.FlagSet, values *hostFlags) {
	defaults := bundle.DefaultPaths()
	flags.StringVar(&values.root, "root", defaults.Root, "immutable BrokerKit release root")
	flags.StringVar(&values.state, "state-dir", defaults.StateDir, "BrokerKit host state directory")
	flags.BoolVar(&values.json, "json", false, "write closed JSON output")
}

func (values hostFlags) installer(development bool) bundle.Installer {
	manager := values.manager
	if manager == nil {
		manager = bundle.NewNativeManager()
	}
	return bundle.Installer{Paths: bundle.Paths{Root: values.root, StateDir: values.state}, Manager: manager, Development: development}
}

func runActivation(ctx context.Context, action string, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("brokerkit system "+action, flag.ContinueOnError)
	flags.SetOutput(stderr)
	var host hostFlags
	bindHostFlags(flags, &host)
	manifestPath := flags.String("manifest", "", "signed runtime bundle manifest")
	artifacts := flags.String("artifacts", "", "directory containing pinned component artifacts")
	signature := flags.String("signature", "", "detached base64 Ed25519 signature")
	publicKey := flags.String("public-key", "", "base64 Ed25519 public key")
	development := flags.Bool("development", false, "allow an unsigned development bundle")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *manifestPath == "" {
		return errors.New("--manifest is required and positional arguments are not accepted")
	}
	if err := validateActivationMode(action, host, *development); err != nil {
		return err
	}
	trustedKey := *publicKey
	needsPin := false
	if !*development {
		var trustErr error
		trustedKey, needsPin, trustErr = bundle.TrustedPublicKey(host.state, *publicKey)
		if trustErr != nil {
			return trustErr
		}
	}
	manifest, data, err := bundle.Load(*manifestPath, *signature, trustedKey, *development)
	if err != nil {
		return err
	}
	if *artifacts == "" {
		*artifacts = filepath.Dir(*manifestPath)
	}
	if action == "plan" {
		return writePlan(stdout, host.json, manifest, *artifacts, host)
	}
	if needsPin {
		if _, err := bundle.PinTrustedPublicKey(host.state, *publicKey); err != nil {
			return err
		}
	}
	if err := host.installer(*development).Activate(ctx, manifest, data, *artifacts); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Activated BrokerKit bundle %s\n", manifest.BundleID)
	return err
}

func validateActivationMode(action string, host hostFlags, development bool) error {
	production := bundle.DefaultPaths()
	if development {
		if action != "plan" && (host.root == production.Root || host.state == production.StateDir) {
			return errors.New("development activation requires isolated --root and --state-dir paths")
		}
		return nil
	}
	if action != "plan" && (host.root != production.Root || host.state != production.StateDir) {
		return errors.New("production activation uses the fixed system root and state directory")
	}
	if action != "plan" && os.Geteuid() != 0 {
		return errors.New("production activation must run as root")
	}
	return nil
}

func writePlan(writer io.Writer, asJSON bool, manifest bundle.Manifest, artifacts string, host hostFlags) error {
	value := struct {
		APIVersion string             `json:"api_version"`
		BundleID   string             `json:"bundle_id"`
		Root       string             `json:"root"`
		StateDir   string             `json:"state_dir"`
		Artifacts  string             `json:"artifacts"`
		Components []bundle.Component `json:"components"`
	}{bundle.APIVersion, manifest.BundleID, host.root, host.state, artifacts, manifest.Components}
	if asJSON {
		return json.NewEncoder(writer).Encode(value)
	}
	_, err := fmt.Fprintf(writer, "Bundle: %s\nRoot: %s\nState: %s\nArtifacts: %s\nComponents: %d\n",
		value.BundleID, value.Root, value.StateDir, value.Artifacts, len(value.Components))
	return err
}

func runStatus(ctx context.Context, action string, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("brokerkit system "+action, flag.ContinueOnError)
	flags.SetOutput(stderr)
	var host hostFlags
	bindHostFlags(flags, &host)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("status does not accept positional arguments")
	}
	report, err := host.installer(false).Status(ctx)
	if err != nil {
		return err
	}
	if host.json {
		if err := json.NewEncoder(stdout).Encode(report); err != nil {
			return err
		}
	} else {
		status := "healthy"
		if !report.Healthy {
			status = "unhealthy"
		}
		_, _ = fmt.Fprintf(stdout, "BrokerKit host: %s\nActive bundle: %s\n", status, report.Activation.ActiveBundleID)
		for _, problem := range report.Problems {
			_, _ = fmt.Fprintf(stdout, "- %s\n", problem)
		}
	}
	if action == "doctor" && !report.Healthy {
		return errors.New("BrokerKit host requires repair")
	}
	return nil
}

func runRollback(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("brokerkit system rollback", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var host hostFlags
	bindHostFlags(flags, &host)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("rollback does not accept positional arguments")
	}
	if err := host.installer(false).Rollback(ctx); err != nil {
		return err
	}
	_, err := fmt.Fprintln(stdout, "Rolled back the BrokerKit host bundle")
	return err
}
