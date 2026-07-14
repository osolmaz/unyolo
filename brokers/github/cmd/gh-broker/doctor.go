package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"strings"

	"github.com/osolmaz/brokerkit/brokers/github/internal/config"
	"github.com/osolmaz/brokerkit/brokers/github/internal/githubdoctor"
	bkdoctor "github.com/osolmaz/brokerkit/doctor"
	"github.com/osolmaz/brokerkit/envfile"
)

func runDoctor(ctx context.Context, stdout io.Writer, stderr io.Writer, args []string) error {
	if len(args) == 0 {
		return exitError{code: 64, message: "usage: gh-broker doctor [github|policy] [flags]"}
	}
	if args[0] == "policy" {
		return runDoctorPolicy(stdout, stderr, args[1:])
	}
	if args[0] != "github" {
		return exitError{code: 64, message: "usage: gh-broker doctor [github|policy] [flags]"}
	}
	command, err := parseDoctorGitHub(stderr, args[1:])
	if err != nil {
		return err
	}
	if command.help {
		return nil
	}
	return executeGitHubDoctor(ctx, stdout, command)
}

type doctorGitHubCommand struct {
	options    githubdoctor.Options
	envFile    string
	jsonOutput bool
	help       bool
}

func executeGitHubDoctor(ctx context.Context, stdout io.Writer, command doctorGitHubCommand) error {
	report, err := loadGitHubDoctorReport(ctx, command.options, command.envFile)
	if err != nil {
		return exitError{code: 64, message: err.Error()}
	}
	return emitDoctorReport(stdout, report, command.jsonOutput)
}

func loadGitHubDoctorReport(ctx context.Context, options githubdoctor.Options, environmentFile string) (bkdoctor.Report, error) {
	cfg, err := loadGitHubDoctorConfig(environmentFile)
	if err != nil {
		return bkdoctor.Report{}, err
	}
	return githubdoctor.Run(ctx, cfg, options)
}

func loadGitHubDoctorConfig(environmentFile string) (config.Config, error) {
	if environmentFile == "" {
		return config.Load()
	}
	values, err := envfile.Load(environmentFile)
	if err != nil {
		return config.Config{}, err
	}
	return config.LoadFromLookup(func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	})
}

func emitDoctorReport(stdout io.Writer, report bkdoctor.Report, jsonOutput bool) error {
	err := writeDoctorReport(stdout, report, jsonOutput)
	if err != nil {
		return err
	}
	return doctorStatusError(report)
}

func doctorStatusError(report bkdoctor.Report) error {
	if code := bkdoctor.ExitCode(report.Status); code != 0 {
		return exitError{code: code}
	}
	return nil
}

func writeDoctorReport(stdout io.Writer, report bkdoctor.Report, jsonOutput bool) error {
	if jsonOutput {
		return bkdoctor.WriteJSON(stdout, report)
	}
	return bkdoctor.WriteText(stdout, report)
}

func parseDoctorGitHub(stderr io.Writer, args []string) (doctorGitHubCommand, error) {
	var output strings.Builder
	fs := flag.NewFlagSet("gh-broker doctor github", flag.ContinueOnError)
	fs.SetOutput(&output)
	agentUser := fs.String("agent-user", "", "agent username to inspect")
	serviceUser := fs.String("service-user", "gh-broker", "broker service username")
	repo := fs.String("repo", "", "configured GitHub repository as owner/name")
	environmentFile := fs.String("env-file", "/etc/gh-broker/env", "installed broker environment file; empty uses process environment only")
	requireProtection := fs.Bool("require-protection", true, "require a ruleset or branch protection on the default branch")
	jsonOutput := fs.Bool("json", false, "write JSON output")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.Copy(stderr, strings.NewReader(output.String()))
			return doctorGitHubCommand{help: true}, nil
		}
		return doctorGitHubCommand{}, exitError{code: 64, message: "invalid doctor github flags"}
	}
	if fs.NArg() != 0 || *repo == "" || *agentUser == "" {
		return doctorGitHubCommand{}, exitError{code: 64, message: "doctor github requires --repo owner/name, --agent-user name, and no positional arguments"}
	}
	return doctorGitHubCommand{
		options: githubdoctor.Options{
			AgentUser:         *agentUser,
			ServiceUser:       *serviceUser,
			Repo:              *repo,
			RequireProtection: *requireProtection,
		},
		envFile:    *environmentFile,
		jsonOutput: *jsonOutput,
	}, nil
}
