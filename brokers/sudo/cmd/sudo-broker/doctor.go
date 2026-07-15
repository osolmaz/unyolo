package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorclient"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/hostcheck"
	"github.com/osolmaz/brokerkit/doctor"
)

type doctorOptions struct {
	agentUser       string
	serviceUser     string
	catalogPath     string
	helperState     string
	helperSocket    string
	clientSecrets   string
	operatorSecrets string
	telegramToken   string
	jsonOutput      bool
	helperTimeout   time.Duration
}

func runDoctor(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	return runDoctorWithReport(ctx, args, stdout, stderr, sudoDoctorReport)
}

func runDoctorWithReport(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer,
	reportFor func(context.Context, doctorOptions) (doctor.Report, error)) error {
	rest, err := doctorHostArgs(args)
	if err != nil {
		return err
	}
	opts, help, err := parseDoctorOptions(rest, stderr)
	if err != nil || help {
		return err
	}
	if err := validateDoctorReportProvider(reportFor); err != nil {
		return err
	}
	report, err := reportFor(ctx, opts)
	if err != nil {
		return err
	}
	if err := writeDoctorReport(stdout, report, opts.jsonOutput); err != nil {
		return err
	}
	return doctorExitError(report)
}

func doctorHostArgs(args []string) ([]string, error) {
	if len(args) == 0 || args[0] != "host" {
		return nil, errors.New("usage: sudo-broker doctor host --agent USER [flags]")
	}
	return args[1:], nil
}

func validateDoctorReportProvider(reportFor func(context.Context, doctorOptions) (doctor.Report, error)) error {
	if reportFor == nil {
		return errors.New("doctor report provider is required")
	}
	return nil
}

func writeDoctorReport(stdout io.Writer, report doctor.Report, jsonOutput bool) error {
	if jsonOutput {
		return doctor.WriteJSON(stdout, report)
	}
	return doctor.WriteText(stdout, report)
}

func doctorExitError(report doctor.Report) error {
	if code := doctor.ExitCode(report.Status); code != 0 {
		return exitError{code: code}
	}
	return nil
}

func parseDoctorOptions(args []string, stderr io.Writer) (doctorOptions, bool, error) {
	// #nosec G101 -- these are standard filesystem paths, not hardcoded credential values.
	opts := doctorOptions{serviceUser: "sudo-broker", catalogPath: "/etc/sudo-broker/catalog.json",
		helperState: "/var/lib/sudo-broker/helper", helperSocket: "/run/sudo-broker/helper.sock",
		clientSecrets: "/etc/sudo-broker/secrets", operatorSecrets: "/etc/sudo-broker/operator-secrets",
		telegramToken: "/etc/sudo-broker/telegram-bot-token", helperTimeout: 3 * time.Second}
	var output strings.Builder
	flags := flag.NewFlagSet("sudo-broker doctor host", flag.ContinueOnError)
	flags.SetOutput(&output)
	flags.StringVar(&opts.agentUser, "agent", "", "unprivileged agent account")
	flags.StringVar(&opts.serviceUser, "service-user", opts.serviceUser, "unprivileged frontend account")
	flags.StringVar(&opts.catalogPath, "catalog", opts.catalogPath, "root-owned command catalog")
	flags.StringVar(&opts.helperState, "helper-state-dir", opts.helperState, "root-owned helper state directory")
	flags.StringVar(&opts.helperSocket, "helper-socket", opts.helperSocket, "helper Unix socket")
	flags.StringVar(&opts.clientSecrets, "client-secrets-file", opts.clientSecrets, "broker client secret file")
	flags.StringVar(&opts.operatorSecrets, "operator-secrets-file", opts.operatorSecrets, "broker operator secret file")
	flags.StringVar(&opts.telegramToken, "telegram-token-file", opts.telegramToken, "Telegram bot token file")
	flags.DurationVar(&opts.helperTimeout, "helper-timeout", opts.helperTimeout, "helper readiness timeout")
	flags.BoolVar(&opts.jsonOutput, "json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.Copy(stderr, strings.NewReader(output.String()))
			return doctorOptions{}, true, nil
		}
		return doctorOptions{}, false, errors.New("invalid doctor flags")
	}
	if err := validateDoctorFlagValues(flags.NArg(), opts); err != nil {
		return doctorOptions{}, false, err
	}
	return opts, false, nil
}

func validateDoctorFlagValues(extraArgs int, opts doctorOptions) error {
	if extraArgs != 0 || strings.TrimSpace(opts.agentUser) == "" || opts.helperTimeout <= 0 || opts.helperTimeout > 30*time.Second {
		return errors.New("doctor host requires --agent and valid bounded flags")
	}
	return validateDoctorPaths(opts)
}

func validateDoctorPaths(opts doctorOptions) error {
	for _, value := range []string{opts.catalogPath, opts.helperState, opts.helperSocket, opts.clientSecrets, opts.operatorSecrets, opts.telegramToken} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return errors.New("doctor paths must be absolute and normalized")
		}
	}
	return nil
}

func sudoDoctorReport(ctx context.Context, opts doctorOptions) (doctor.Report, error) {
	return sudoDoctorReportWith(ctx, opts, doctorDependencies{
		lookupIdentity:   doctor.LookupIdentity,
		validateRootFile: hostcheck.ValidateRootFile, validateRootDirectory: hostcheck.ValidateRootDirectory,
		validateSocket: hostcheck.ValidateStaleSocket, kernelSafety: hostcheck.KernelExecutionSafety,
		helperReady: func(ctx context.Context, socket string, timeout time.Duration) error {
			return (&executorclient.Client{SocketPath: socket, Timeout: timeout}).Ready(ctx)
		},
	})
}

type doctorDependencies struct {
	lookupIdentity        func(string) (doctor.Identity, error)
	validateRootFile      func(string) error
	validateRootDirectory func(string) error
	validateSocket        func(string, uint32) error
	kernelSafety          func() (bool, error)
	helperReady           func(context.Context, string, time.Duration) error
}

func sudoDoctorReportWith(ctx context.Context, opts doctorOptions, deps doctorDependencies) (doctor.Report, error) {
	agent, err := deps.lookupIdentity(opts.agentUser)
	if err != nil {
		return doctor.Report{}, err
	}
	serviceIdentity, err := deps.lookupIdentity(opts.serviceUser)
	if err != nil {
		return doctor.Report{}, err
	}
	checks := []doctor.Check{doctor.RootEquivalentCheck(agent), doctor.SeparationCheck(agent, serviceIdentity)}
	checks = append(checks,
		hostDoctorCheck("catalog_trusted", "catalog is root-owned and immutable to non-root users", deps.validateRootFile(opts.catalogPath)),
		hostDoctorCheck("helper_state_trusted", "helper state directory is root-owned and immutable to non-root users", deps.validateRootDirectory(opts.helperState)),
		hostDoctorCheck("helper_socket_trusted", "helper socket and parent ownership are valid", deps.validateSocket(opts.helperSocket, uint32(serviceIdentity.UID))), // #nosec G115 -- OS uid is non-negative.
	)
	strong, kernelErr := deps.kernelSafety()
	if kernelErr != nil {
		checks = append(checks, doctor.Check{Status: doctor.CheckFail, Name: "kernel_execution_safety", Message: "required descriptor-safe execution primitives are unavailable"})
	} else if !strong {
		checks = append(checks, doctor.Check{Status: doctor.CheckWarn, Name: "kernel_execution_safety", Message: "platform uses immediate path revalidation instead of Linux descriptor execution"})
	} else {
		checks = append(checks, doctor.Check{Status: doctor.CheckPass, Name: "kernel_execution_safety", Message: "descriptor-safe execution primitives are available"})
	}
	readyCtx, cancel := context.WithTimeout(ctx, opts.helperTimeout)
	defer cancel()
	readyErr := deps.helperReady(readyCtx, opts.helperSocket, opts.helperTimeout)
	checks = append(checks, hostDoctorCheck("helper_ready", "privileged helper authenticated and answered the bounded readiness probe", readyErr))
	report := doctor.NewReport(agent, checks...)
	credentials := []doctor.CredentialStatus{
		doctor.CredentialFileStatus("broker-client", opts.clientSecrets, time.Now().UTC(), doctor.DefaultCredentialRotationAge, time.Time{}, doctor.CredentialRevocationLocal),
		doctor.CredentialFileStatus("broker-operator", opts.operatorSecrets, time.Now().UTC(), doctor.DefaultCredentialRotationAge, time.Time{}, doctor.CredentialRevocationLocal),
		doctor.CredentialFileStatus("telegram-bot", opts.telegramToken, time.Now().UTC(), doctor.DefaultCredentialRotationAge, time.Time{}, doctor.CredentialRevocationManual),
	}
	return doctor.WithCredentials(report, credentials...), nil
}

func hostDoctorCheck(name string, success string, err error) doctor.Check {
	if err != nil {
		return doctor.Check{Status: doctor.CheckFail, Name: name, Message: name + " check failed"}
	}
	return doctor.Check{Status: doctor.CheckPass, Name: name, Message: success}
}
