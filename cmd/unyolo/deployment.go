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

	deploymentplan "github.com/osolmaz/unyolo/deployment/plan"
	"github.com/osolmaz/unyolo/deployment/profile"
	unyolocli "github.com/osolmaz/unyolo/internal/cli"
	"github.com/osolmaz/unyolo/internal/host/bundle"
	hostdeployment "github.com/osolmaz/unyolo/internal/host/deployment"
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
	flags.StringVar(&values.profile, "profile", "", "deployment source directory `DIR`")
	flags.StringVar(&values.root, "root", defaults.Root, "immutable unYOLO release `DIR`")
	flags.StringVar(&values.state, "state-dir", defaults.StateDir, "unYOLO host state `DIR`")
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

type profileLockFlags struct {
	path  string
	check bool
}

func bindProfileLockFlags(output io.Writer) (*flag.FlagSet, *profileLockFlags) {
	flags := flag.NewFlagSet("unyolo system profile lock", flag.ContinueOnError)
	flags.SetOutput(output)
	values := &profileLockFlags{}
	flags.StringVar(&values.path, "profile", "", "deployment source directory `DIR`")
	flags.BoolVar(&values.check, "check", false, "fail if locking would change files")
	return flags, values
}

func newProfileLockFlagSet(output io.Writer) *flag.FlagSet {
	flags, _ := bindProfileLockFlags(output)
	return flags
}

func runProfileLock(args []string, stdout, stderr io.Writer) error {
	flags, values := bindProfileLockFlags(stderr)
	if err := unyolocli.Parse(flags, args); err != nil {
		return err
	}
	if flags.NArg() != 0 || values.path == "" || !filepath.IsAbs(values.path) {
		return unyolocli.Usage(errors.New("--profile must be an absolute deployment source directory"))
	}
	if err := profile.Lock(values.path, values.check); err != nil {
		return err
	}
	if values.check {
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
	}{"unyolo.io/host-validation/v1", snapshot.Deployment.Name, snapshot.Digest, snapshot.Manifest.BundleID, componentIDs(snapshot)}
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
			return unyolocli.Usage(errors.New("--output must be absolute"))
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

func bindDeploymentFlagSet(action string, output io.Writer) (*flag.FlagSet, *deploymentFlags) {
	flags := flag.NewFlagSet("unyolo system "+action, flag.ContinueOnError)
	flags.SetOutput(output)
	values := &deploymentFlags{}
	bindDeploymentFlags(flags, values)
	return flags, values
}

func newDeploymentFlagSetFactory(action string) unyolocli.FlagSetFactory {
	return func(output io.Writer) *flag.FlagSet {
		flags, _ := bindDeploymentFlagSet(action, output)
		return flags
	}
}

func parseDeploymentFlags(action string, args []string, stderr io.Writer) (deploymentFlags, error) {
	flags, values := bindDeploymentFlagSet(action, stderr)
	if err := unyolocli.Parse(flags, args); err != nil {
		return deploymentFlags{}, err
	}
	if flags.NArg() != 0 {
		return deploymentFlags{}, unyolocli.Usage(fmt.Errorf("system %s does not accept positional arguments", action))
	}
	if err := values.validate(action); err != nil {
		return deploymentFlags{}, unyolocli.Usage(err)
	}
	return *values, nil
}

type planCLIFlags struct {
	deploymentFlags
	output string
}

func bindPlanFlags(output io.Writer) (*flag.FlagSet, *planCLIFlags) {
	flags := flag.NewFlagSet("unyolo system plan", flag.ContinueOnError)
	flags.SetOutput(output)
	values := &planCLIFlags{}
	bindDeploymentFlags(flags, &values.deploymentFlags)
	flags.StringVar(&values.output, "output", "", "write canonical plan JSON to `FILE`")
	return flags, values
}

func newPlanFlagSet(output io.Writer) *flag.FlagSet {
	flags, _ := bindPlanFlags(output)
	return flags
}

func parsePlanFlags(args []string, stderr io.Writer) (deploymentFlags, string, error) {
	flags, values := bindPlanFlags(stderr)
	if err := unyolocli.Parse(flags, args); err != nil {
		return deploymentFlags{}, "", err
	}
	if flags.NArg() != 0 {
		return deploymentFlags{}, "", unyolocli.Usage(errors.New("system plan does not accept positional arguments"))
	}
	if err := values.validate("plan"); err != nil {
		return deploymentFlags{}, "", unyolocli.Usage(err)
	}
	return values.deploymentFlags, values.output, nil
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

type applyCLIFlags struct {
	deploymentFlags
	expected string
	secrets  secretFlags
}

func bindApplyFlags(output io.Writer) (*flag.FlagSet, *applyCLIFlags) {
	flags := flag.NewFlagSet("unyolo system apply", flag.ContinueOnError)
	flags.SetOutput(output)
	values := &applyCLIFlags{}
	bindDeploymentFlags(flags, &values.deploymentFlags)
	flags.StringVar(&values.expected, "expect-plan", "", "exact reviewed plan `DIGEST`")
	flags.Var(&values.secrets, "secret-file", "credential slot `NAME=/absolute/path`; repeatable")
	return flags, values
}

func newApplyFlagSet(output io.Writer) *flag.FlagSet {
	flags, _ := bindApplyFlags(output)
	return flags
}

func parseApplyFlags(args []string, stderr io.Writer) (deploymentFlags, string, []hostdeployment.SecretSource, error) {
	flags, values := bindApplyFlags(stderr)
	if err := unyolocli.Parse(flags, args); err != nil {
		return deploymentFlags{}, "", nil, err
	}
	if flags.NArg() != 0 || values.expected == "" {
		return deploymentFlags{}, "", nil, unyolocli.Usage(errors.New("--expect-plan is required and positional arguments are not accepted"))
	}
	if err := values.validate("apply"); err != nil {
		return deploymentFlags{}, "", nil, unyolocli.Usage(err)
	}
	return values.deploymentFlags, values.expected, values.secrets, nil
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
