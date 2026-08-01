package main

import (
	"context"
	"fmt"
	"io"

	unyolocli "github.com/osolmaz/unyolo/internal/cli"
)

func newCLIApplication() *unyolocli.App {
	app := &unyolocli.App{
		Name:             "unyolo",
		Summary:          "unYOLO gives agents controlled access to your credentials.",
		Description:      "Set up credential services, connect agents, and review every privileged change before it is applied.",
		Version:          version,
		EnableCompletion: true,
	}
	app.Commands = []*unyolocli.Command{
		{
			Name: "setup", Summary: "Set up unYOLO on this computer",
			Description: "Choose what to install, review the plan, and apply it with explicit approval.",
			Usage:       "[flags]", Flags: newSetupFlagSet,
			HiddenFlags: map[string]bool{"bootstrap-stage": true},
			Examples:    []string{"unyolo setup", "unyolo setup --accessible", "unyolo setup --new"},
			Run:         runGuidedSetup,
		},
		{
			Name: "status", Summary: "Show installation and setup status",
			Description: "Show the saved installation and any setup sessions for the current account.",
			Usage:       "[flags]", Flags: newSetupStatusFlagSet,
			Examples: []string{"unyolo status", "unyolo status --json"},
			Run: func(_ context.Context, args []string, stdout, stderr io.Writer) error {
				return runSetupStatus(args, stdout, stderr)
			},
		},
		lifecycleCommand("repair", "Repair the current installation", "Rebuild and reapply the saved installation without changing its policy.", newRepairFlagSet, runSetupRepair),
		lifecycleCommand("reconfigure", "Change the current installation", "Review changes to providers, approvers, or agent connections and apply a new plan.", newReconfigureFlagSet, runSetupReconfigure),
		{
			Name: "remove", Summary: "Safely remove an installation",
			Description: "Remove only unchanged resources proven to belong to the installation. Credentials and provider data require separate confirmation.",
			Usage:       "[flags]", Flags: newRemoveFlagSet,
			HiddenFlags: map[string]bool{"bootstrap-stage": true},
			Examples:    []string{"unyolo remove", "unyolo remove --remove-state"},
			Run:         runSetupRemove,
		},
		{
			Name: "session", Summary: "Manage unfinished setup sessions",
			Description: "List or discard unfinished setup answers. Session files never contain provider credentials.",
			Children: []*unyolocli.Command{
				{
					Name: "list", Summary: "List setup sessions", Description: "List saved setup sessions for the current account.",
					Usage: "[flags]", Flags: newSessionListFlagSet,
					Examples: []string{"unyolo session list", "unyolo session list --json"},
					Run: func(_ context.Context, args []string, stdout, stderr io.Writer) error {
						return runSessionList(args, stdout, stderr)
					},
				},
				{
					Name: "discard", Summary: "Discard unfinished setup answers", Description: "Delete one unfinished setup session, or all incomplete sessions after explicit confirmation.",
					Usage: "--confirm [--all | <session-id>]", Flags: newSessionDiscardFlagSet,
					RequiredFlags: []string{"confirm"},
					Examples:      []string{"unyolo session discard --confirm 0123456789abcdef0123456789abcdef", "unyolo session discard --confirm --all"},
					Run: func(_ context.Context, args []string, stdout, stderr io.Writer) error {
						return runSetupDiscard(args, stdout, stderr)
					},
				},
			},
		},
		{
			Name: "version", Summary: "Print the installed version", Group: "Utilities",
			Description: "Print the unYOLO command version.",
			Examples:    []string{"unyolo version", "unyolo --version"},
			Run: func(_ context.Context, args []string, stdout, _ io.Writer) error {
				if len(args) != 0 {
					return unyolocli.Usage(fmt.Errorf("version does not accept positional arguments"))
				}
				_, err := fmt.Fprintln(stdout, version)
				return err
			},
		},
		systemCommand(),
	}
	return app
}

func lifecycleCommand(name, summary, description string, flags unyolocli.FlagSetFactory, handler unyolocli.Handler) *unyolocli.Command {
	return &unyolocli.Command{
		Name: name, Summary: summary, Description: description, Usage: "[flags]", Flags: flags,
		HiddenFlags: map[string]bool{"bootstrap-stage": true},
		Examples:    []string{"unyolo " + name, "unyolo " + name + " --accessible"},
		Run:         handler,
	}
}

func systemCommand() *unyolocli.Command {
	return &unyolocli.Command{
		Name: "system", Summary: "Run low-level host operations", Group: "Advanced",
		Description: "Validate, plan, apply, verify, and inspect signed host deployment data. These commands are intended for release tooling and administrators.",
		Children: []*unyolocli.Command{
			{
				Name: "profile", Summary: "Manage locked deployment profiles", Children: []*unyolocli.Command{
					{
						Name: "lock", Summary: "Lock a deployment profile to exact artifacts", Description: "Resolve and record every bounded artifact referenced by a deployment profile.",
						Usage: "--profile DIR [--check]", Flags: newProfileLockFlagSet, RequiredFlags: []string{"profile"},
						Examples: []string{"unyolo system profile lock --profile /absolute/path", "unyolo system profile lock --profile /absolute/path --check"},
						Run: func(_ context.Context, args []string, stdout, stderr io.Writer) error {
							return runProfileLock(args, stdout, stderr)
						},
					},
				},
			},
			deploymentSystemCommand("validate", "Validate a deployment profile", newDeploymentFlagSetFactory("validate"), runDeploymentValidate),
			deploymentSystemCommand("plan", "Create a reviewed deployment plan", newPlanFlagSet, runDeploymentPlan),
			deploymentSystemCommand("apply", "Apply an exact reviewed deployment plan", newApplyFlagSet, runDeploymentApply),
			deploymentSystemCommand("verify", "Verify the active deployment", newDeploymentFlagSetFactory("verify"), runDeploymentVerify),
			deploymentSystemCommand("export", "Export observed deployment state", newDeploymentFlagSetFactory("export"), runDeploymentExport),
			activationSystemCommand("install", "Install a signed host runtime"),
			activationSystemCommand("upgrade", "Upgrade the signed host runtime"),
			statusSystemCommand("status", "Show low-level host runtime status"),
			statusSystemCommand("doctor", "Diagnose low-level host runtime problems"),
			{
				Name: "rollback", Summary: "Roll back the active host runtime", Description: "Switch the host back to the previous verified runtime bundle.",
				Usage: "[flags]", Flags: newHostFlagSetFactory("unyolo system rollback"),
				Examples: []string{"sudo /opt/unyolo/bootstrap/v<version>/unyolo system rollback"}, Run: runRollback,
			},
			{
				Name: "setup-worker", Hidden: true, Flags: newSetupWorkerFlagSet,
				Run: runSetupWorker,
			},
		},
	}
}

func deploymentSystemCommand(name, summary string, flags unyolocli.FlagSetFactory, handler unyolocli.Handler) *unyolocli.Command {
	example := "unyolo system " + name + " --profile /absolute/deployment"
	switch name {
	case "plan":
		example += " --output /tmp/plan.json"
	case "apply":
		example += " --expect-plan sha256:<digest>"
	case "validate", "verify", "export":
		example += " --json"
	}
	command := &unyolocli.Command{
		Name: name, Summary: summary, Description: summary + " using exact release-bound inputs.",
		Usage: "--profile DIR [flags]", Flags: flags, RequiredFlags: []string{"profile"}, Run: handler,
		Examples: []string{example},
	}
	if name == "apply" {
		command.RequiredFlags = append(command.RequiredFlags, "expect-plan")
	}
	return command
}

func activationSystemCommand(name, summary string) *unyolocli.Command {
	return &unyolocli.Command{
		Name: name, Summary: summary, Description: summary + " from an exact signed manifest and pinned artifacts.",
		Usage: "--manifest FILE [flags]", Flags: newActivationFlagSetFactory(name), RequiredFlags: []string{"manifest"},
		Examples: []string{"sudo /opt/unyolo/bootstrap/v<version>/unyolo system " + name + " --manifest /absolute/manifest.json --signature /absolute/manifest.sig --public-key /absolute/release.pub"},
		Run: func(ctx context.Context, args []string, stdout, stderr io.Writer) error {
			return runActivation(ctx, name, args, stdout, stderr)
		},
	}
}

func statusSystemCommand(name, summary string) *unyolocli.Command {
	return &unyolocli.Command{
		Name: name, Summary: summary, Description: summary + ".", Usage: "[flags]",
		Flags:    newHostFlagSetFactory("unyolo system " + name),
		Examples: []string{"sudo /opt/unyolo/bootstrap/v<version>/unyolo system " + name, "sudo /opt/unyolo/bootstrap/v<version>/unyolo system " + name + " --json"},
		Run: func(ctx context.Context, args []string, stdout, stderr io.Writer) error {
			return runStatus(ctx, name, args, stdout, stderr)
		},
	}
}
