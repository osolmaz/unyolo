// Package statecmd exposes provider-neutral offline state maintenance commands.
package statecmd

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/osolmaz/brokerkit/state"
)

// Run executes one offline state maintenance command.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: state <check|backup|restore|export>")
	}
	switch args[0] {
	case "check":
		return runCheck(ctx, args[1:], stdout, stderr)
	case "backup":
		return runBackup(ctx, args[1:], stdout, stderr)
	case "restore":
		return runRestore(ctx, args[1:], stdout, stderr)
	case "export":
		return runExport(ctx, args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown state command %q", args[0])
	}
}

func runCheck(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("state check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var directory string
	var full bool
	flags.StringVar(&directory, "state-dir", "", "absolute broker state directory")
	flags.BoolVar(&full, "full", false, "run the full SQLite integrity check")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !absoluteClean(directory) {
		return errors.New("state check requires --state-dir with an absolute clean path")
	}
	database, err := state.OpenExisting(ctx, directory, state.Options{})
	if err != nil {
		return err
	}
	defer database.Close()
	report, err := database.Check(ctx, full)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(report)
}

func runBackup(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	directory, output, err := maintenanceFlags("state backup", args, stderr, "output", "absolute new backup directory")
	if err != nil {
		return err
	}
	database, err := state.OpenExisting(ctx, directory, state.Options{})
	if err != nil {
		return err
	}
	defer database.Close()
	manifest, err := database.Backup(ctx, output)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(struct {
		Output   string               `json:"output"`
		Manifest state.BackupManifest `json:"manifest"`
	}{Output: output, Manifest: manifest})
}

func runRestore(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	directory, backup, err := maintenanceFlags("state restore", args, stderr, "backup", "absolute backup directory")
	if err != nil {
		return err
	}
	if err := state.Restore(ctx, directory, backup); err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(map[string]string{"state_dir": directory, "status": "restored"})
}

func runExport(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	directory, output, err := maintenanceFlags("state export", args, stderr, "output", "absolute new redacted JSON file")
	if err != nil {
		return err
	}
	database, err := state.OpenExisting(ctx, directory, state.Options{})
	if err != nil {
		return err
	}
	defer database.Close()
	if err := database.Export(ctx, output); err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(map[string]string{"output": output, "status": "exported"})
}

func maintenanceFlags(name string, args []string, stderr io.Writer, destinationName, destinationUsage string) (string, string, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	var directory, destination string
	flags.StringVar(&directory, "state-dir", "", "absolute broker state directory")
	flags.StringVar(&destination, destinationName, "", destinationUsage)
	if err := flags.Parse(args); err != nil {
		return "", "", err
	}
	if flags.NArg() != 0 || !absoluteClean(directory) || !absoluteClean(destination) {
		return "", "", fmt.Errorf("%s requires --state-dir and --%s with absolute clean paths", name, destinationName)
	}
	return directory, destination, nil
}

func absoluteClean(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}
