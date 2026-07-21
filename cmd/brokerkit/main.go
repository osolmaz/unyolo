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
var newNativeManager = bundle.NewNativeManager

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
		return systemUsageError()
	}
	buildinfo.Version = version
	handlers := map[string]func() error{
		"plan":     func() error { return runActivation(ctx, "plan", args[2:], stdout, stderr) },
		"install":  func() error { return runActivation(ctx, "install", args[2:], stdout, stderr) },
		"upgrade":  func() error { return runActivation(ctx, "upgrade", args[2:], stdout, stderr) },
		"status":   func() error { return runStatus(ctx, "status", args[2:], stdout, stderr) },
		"doctor":   func() error { return runStatus(ctx, "doctor", args[2:], stdout, stderr) },
		"rollback": func() error { return runRollback(ctx, args[2:], stdout, stderr) },
	}
	handler, ok := handlers[args[1]]
	if !ok {
		return systemUsageError()
	}
	return handler()
}

func systemUsageError() error {
	return errors.New("usage: brokerkit system <plan|install|upgrade|status|doctor|rollback>")
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
		manager = newNativeManager()
	}
	return bundle.Installer{Paths: bundle.Paths{Root: values.root, StateDir: values.state}, Manager: manager, Development: development}
}

type activationOptions struct {
	host         hostFlags
	manifestPath string
	artifacts    string
	signature    string
	publicKey    string
	development  bool
}

func runActivation(ctx context.Context, action string, args []string, stdout, stderr io.Writer) error {
	options, err := parseActivationOptions(action, args, stderr)
	if err != nil {
		return err
	}
	manifest, data, needsPin, err := loadActivationBundle(options)
	if err != nil {
		return err
	}
	if action == "plan" {
		return writePlan(stdout, options.host.json, manifest, options.artifacts, options.host)
	}
	return activateBundle(ctx, stdout, options, manifest, data, needsPin)
}

func activateBundle(ctx context.Context, stdout io.Writer, options activationOptions, manifest bundle.Manifest, data []byte, needsPin bool) error {
	if needsPin {
		if _, err := bundle.PinTrustedPublicKey(options.host.state, options.publicKey); err != nil {
			return err
		}
	}
	if err := options.host.installer(options.development).Activate(ctx, manifest, data, options.artifacts); err != nil {
		return err
	}
	_, err := fmt.Fprintf(stdout, "Activated BrokerKit bundle %s\n", manifest.BundleID)
	return err
}

func parseActivationOptions(action string, args []string, stderr io.Writer) (activationOptions, error) {
	flags := flag.NewFlagSet("brokerkit system "+action, flag.ContinueOnError)
	flags.SetOutput(stderr)
	var options activationOptions
	bindHostFlags(flags, &options.host)
	flags.StringVar(&options.manifestPath, "manifest", "", "signed runtime bundle manifest")
	flags.StringVar(&options.artifacts, "artifacts", "", "directory containing pinned component artifacts")
	flags.StringVar(&options.signature, "signature", "", "detached base64 Ed25519 signature")
	flags.StringVar(&options.publicKey, "public-key", "", "base64 Ed25519 public key")
	flags.BoolVar(&options.development, "development", false, "allow an unsigned development bundle")
	if err := flags.Parse(args); err != nil {
		return activationOptions{}, err
	}
	if flags.NArg() != 0 || options.manifestPath == "" {
		return activationOptions{}, errors.New("--manifest is required and positional arguments are not accepted")
	}
	if err := validateActivationMode(action, options.host, options.development); err != nil {
		return activationOptions{}, err
	}
	if options.artifacts == "" {
		options.artifacts = filepath.Dir(options.manifestPath)
	}
	return options, nil
}

func loadActivationBundle(options activationOptions) (bundle.Manifest, []byte, bool, error) {
	trustedKey := options.publicKey
	needsPin := false
	if !options.development {
		var trustErr error
		trustedKey, needsPin, trustErr = bundle.TrustedPublicKey(options.host.state, options.publicKey)
		if trustErr != nil {
			return bundle.Manifest{}, nil, false, trustErr
		}
	}
	manifest, data, err := bundle.Load(options.manifestPath, options.signature, trustedKey, options.development)
	if err != nil {
		return bundle.Manifest{}, nil, false, err
	}
	return manifest, data, needsPin, nil
}

func validateActivationMode(action string, host hostFlags, development bool) error {
	production := bundle.DefaultPaths()
	if development {
		return validateDevelopmentActivation(action, host, production)
	}
	return validateProductionActivation(action, host, production)
}

func validateDevelopmentActivation(action string, host hostFlags, production bundle.Paths) error {
	if action != "plan" && (host.root == production.Root || host.state == production.StateDir) {
		return errors.New("development activation requires isolated --root and --state-dir paths")
	}
	return nil
}

func validateProductionActivation(action string, host hostFlags, production bundle.Paths) error {
	if action == "plan" {
		return nil
	}
	if host.root != production.Root || host.state != production.StateDir {
		return errors.New("production activation uses the fixed system root and state directory")
	}
	if os.Geteuid() != 0 {
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
	host, err := parseHostOptions("brokerkit system "+action, args, stderr, "status")
	if err != nil {
		return err
	}
	report, err := host.installer(false).Status(ctx)
	if err != nil {
		return err
	}
	if err := writeStatus(stdout, host.json, report); err != nil {
		return err
	}
	if action == "doctor" && !report.Healthy {
		return errors.New("BrokerKit host requires repair")
	}
	return nil
}

func parseHostOptions(name string, args []string, stderr io.Writer, positionalLabel string) (hostFlags, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	var host hostFlags
	bindHostFlags(flags, &host)
	if err := flags.Parse(args); err != nil {
		return hostFlags{}, err
	}
	if flags.NArg() != 0 {
		return hostFlags{}, fmt.Errorf("%s does not accept positional arguments", positionalLabel)
	}
	return host, nil
}

func writeStatus(stdout io.Writer, asJSON bool, report bundle.Report) error {
	if asJSON {
		return json.NewEncoder(stdout).Encode(report)
	}
	status := "healthy"
	if !report.Healthy {
		status = "unhealthy"
	}
	if _, err := fmt.Fprintf(stdout, "BrokerKit host: %s\nActive bundle: %s\n", status, report.Activation.ActiveBundleID); err != nil {
		return err
	}
	for _, problem := range report.Problems {
		if _, err := fmt.Fprintf(stdout, "- %s\n", problem); err != nil {
			return err
		}
	}
	return nil
}

func runRollback(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	host, err := parseHostOptions("brokerkit system rollback", args, stderr, "rollback")
	if err != nil {
		return err
	}
	if err := host.installer(false).Rollback(ctx); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "Rolled back the BrokerKit host bundle")
	return err
}
