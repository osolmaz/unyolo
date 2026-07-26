package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	deploymentplan "github.com/osolmaz/brokerkit/deployment/plan"
	"github.com/osolmaz/brokerkit/deployment/profile"
	"github.com/osolmaz/brokerkit/internal/host/bundle"
	hostdeployment "github.com/osolmaz/brokerkit/internal/host/deployment"
)

type deploymentFlags struct {
	profile     string
	root        string
	state       string
	development bool
	jsonOutput  bool
}

func bindDeploymentFlags(flags *flag.FlagSet, values *deploymentFlags) {
	defaults := bundle.DefaultPaths()
	flags.StringVar(&values.profile, "profile", "", "deployment pack directory")
	flags.StringVar(&values.root, "root", defaults.Root, "immutable BrokerKit release root")
	flags.StringVar(&values.state, "state-dir", defaults.StateDir, "BrokerKit host state directory")
	flags.BoolVar(&values.development, "development", false, "use isolated nonproduction host paths")
	flags.BoolVar(&values.jsonOutput, "json", false, "write closed JSON output")
}

func (values deploymentFlags) validate(action string) error {
	if values.profile == "" || !filepath.IsAbs(values.profile) {
		return errors.New("--profile must be an absolute deployment pack directory")
	}
	production := bundle.DefaultPaths()
	if values.development {
		if values.root == production.Root || values.state == production.StateDir {
			return errors.New("development deployment requires isolated --root and --state-dir paths")
		}
	} else if action != "validate" && (values.root != production.Root || values.state != production.StateDir) {
		return errors.New("production deployment uses fixed host paths")
	}
	return nil
}

func (values deploymentFlags) engine() (*hostdeployment.Engine, error) {
	return hostdeployment.New(hostdeployment.Options{
		Paths:       bundle.Paths{Root: values.root, StateDir: values.state},
		Development: values.development,
	})
}

func runProfileCommand(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "lock" {
		return errors.New("usage: brokerkit system profile lock --profile DIR [--check]")
	}
	flags := flag.NewFlagSet("brokerkit system profile lock", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("profile", "", "deployment pack directory")
	check := flags.Bool("check", false, "fail if locking would change files")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *path == "" || !filepath.IsAbs(*path) {
		return errors.New("--profile must be an absolute deployment pack directory")
	}
	if err := profile.Lock(*path, *check); err != nil {
		return err
	}
	if *check {
		_, err := fmt.Fprintln(stdout, "Deployment profile lock is current")
		return err
	}
	_, err := fmt.Fprintln(stdout, "Locked deployment profile")
	return err
}

func runDeploymentValidate(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	values, err := parseDeploymentFlags("validate", args, stderr)
	if err != nil {
		return err
	}
	engine, err := values.engine()
	if err != nil {
		return err
	}
	snapshot, err := engine.Validate(ctx, values.profile)
	if err != nil {
		return err
	}
	result := struct {
		APIVersion string   `json:"api_version"`
		Name       string   `json:"name"`
		Digest     string   `json:"digest"`
		BundleID   string   `json:"bundle_id"`
		Components []string `json:"components"`
	}{"brokerkit.io/host-validation/v1", snapshot.Deployment.Name, snapshot.Digest, snapshot.Manifest.BundleID, componentIDs(snapshot)}
	return writeDeploymentResult(stdout, values.jsonOutput, result,
		fmt.Sprintf("Validated deployment %s\nDigest: %s\nRuntime: %s\nComponents: %s\n", result.Name, result.Digest, result.BundleID, strings.Join(result.Components, ", ")))
}

func runDeploymentPlan(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	values, output, err := parsePlanFlags(args, stderr)
	if err != nil {
		return err
	}
	engine, err := values.engine()
	if err != nil {
		return err
	}
	planned, err := engine.Plan(ctx, values.profile)
	if err != nil {
		return err
	}
	data, err := deploymentplan.Marshal(planned.Plan)
	if err != nil {
		return err
	}
	if output != "" {
		if !filepath.IsAbs(output) {
			return errors.New("--output must be absolute")
		}
		if err := os.WriteFile(output, data, 0o600); err != nil { // #nosec G703 -- explicit operator-selected plan output.
			return err
		}
	}
	if values.jsonOutput {
		_, err = stdout.Write(data)
		return err
	}
	_, err = fmt.Fprintf(stdout, "Deployment: %s\nKind: %s\nPlan: %s\nActions: %d\n", planned.Plan.DeploymentName, planned.Plan.Kind, planned.Plan.Digest, len(planned.Plan.Actions))
	return err
}

func runDeploymentApply(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	values, expected, secrets, err := parseApplyFlags(args, stderr)
	if err != nil {
		return err
	}
	engine, err := values.engine()
	if err != nil {
		return err
	}
	report, err := engine.Apply(ctx, values.profile, expected, secrets)
	if err != nil {
		return err
	}
	return writeDeploymentResult(stdout, values.jsonOutput, report,
		fmt.Sprintf("Applied and verified deployment %s\nRuntime: %s\n", report.DeploymentName, report.RuntimeBundleID))
}

func runDeploymentVerify(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	values, err := parseDeploymentFlags("verify", args, stderr)
	if err != nil {
		return err
	}
	engine, err := values.engine()
	if err != nil {
		return err
	}
	report, err := engine.Verify(ctx, values.profile)
	if writeErr := writeDeploymentResult(stdout, values.jsonOutput, report,
		fmt.Sprintf("Verified deployment %s\nRuntime: %s\nComponents: %d\n", report.DeploymentName, report.RuntimeBundleID, len(report.Components))); writeErr != nil {
		return writeErr
	}
	return err
}

func runDeploymentExport(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	values, err := parseDeploymentFlags("export", args, stderr)
	if err != nil {
		return err
	}
	engine, err := values.engine()
	if err != nil {
		return err
	}
	report, verifyErr := engine.ExportObserved(ctx, values.profile)
	if err := json.NewEncoder(stdout).Encode(report); err != nil {
		return err
	}
	return verifyErr
}

func parseDeploymentFlags(action string, args []string, stderr io.Writer) (deploymentFlags, error) {
	flags := flag.NewFlagSet("brokerkit system "+action, flag.ContinueOnError)
	flags.SetOutput(stderr)
	var values deploymentFlags
	bindDeploymentFlags(flags, &values)
	if err := flags.Parse(args); err != nil {
		return deploymentFlags{}, err
	}
	if flags.NArg() != 0 {
		return deploymentFlags{}, fmt.Errorf("system %s does not accept positional arguments", action)
	}
	return values, values.validate(action)
}

func parsePlanFlags(args []string, stderr io.Writer) (deploymentFlags, string, error) {
	flags := flag.NewFlagSet("brokerkit system plan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var values deploymentFlags
	bindDeploymentFlags(flags, &values)
	output := flags.String("output", "", "write canonical plan JSON")
	if err := flags.Parse(args); err != nil {
		return deploymentFlags{}, "", err
	}
	if flags.NArg() != 0 {
		return deploymentFlags{}, "", errors.New("system plan does not accept positional arguments")
	}
	return values, *output, values.validate("plan")
}

type secretFlags []hostdeployment.SecretSource

func (values *secretFlags) String() string { return "" }
func (values *secretFlags) Set(raw string) error {
	name, path, found := strings.Cut(raw, "=")
	if !found || name == "" || path == "" {
		return errors.New("secret binding must use NAME=/absolute/path")
	}
	for _, value := range *values {
		if value.Name == name {
			return fmt.Errorf("secret slot %q is duplicated", name)
		}
	}
	*values = append(*values, hostdeployment.SecretSource{Name: name, Path: path})
	return nil
}

func parseApplyFlags(args []string, stderr io.Writer) (deploymentFlags, string, []hostdeployment.SecretSource, error) {
	flags := flag.NewFlagSet("brokerkit system apply", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var values deploymentFlags
	bindDeploymentFlags(flags, &values)
	expected := flags.String("expect-plan", "", "exact reviewed plan digest")
	var secrets secretFlags
	flags.Var(&secrets, "secret-file", "credential slot NAME=/absolute/path; repeatable")
	if err := flags.Parse(args); err != nil {
		return deploymentFlags{}, "", nil, err
	}
	if flags.NArg() != 0 || *expected == "" {
		return deploymentFlags{}, "", nil, errors.New("--expect-plan is required and positional arguments are not accepted")
	}
	if err := values.validate("apply"); err != nil {
		return deploymentFlags{}, "", nil, err
	}
	return values, *expected, secrets, nil
}

func componentIDs(snapshot profile.Snapshot) []string {
	result := make([]string, 0, len(snapshot.Deployment.Components))
	for _, component := range snapshot.Deployment.Components {
		result = append(result, component.ID)
	}
	return result
}

func writeDeploymentResult(writer io.Writer, asJSON bool, value any, text string) error {
	if asJSON {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(value)
	}
	_, err := io.WriteString(writer, text)
	return err
}
