package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/osolmaz/brokerkit/brokers/github/internal/upstreamdrift"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	return runWith(checkRuntime{
		args:         os.Args[1:],
		stdout:       os.Stdout,
		timeout:      5 * time.Minute,
		root:         repositoryRoot,
		loadPinned:   upstreamdrift.LoadPinned,
		fetchCurrent: fetchCurrentFromGitHub,
	})
}

type checkRuntime struct {
	args         []string
	stdout       io.Writer
	timeout      time.Duration
	root         func() (string, error)
	loadPinned   func(string) (upstreamdrift.SnapshotSet, error)
	fetchCurrent func(context.Context, []byte) (upstreamdrift.SnapshotSet, error)
}

func runWith(runtime checkRuntime) error {
	options, err := parseOptions(runtime.args)
	if err != nil {
		return err
	}
	root, err := runtime.root()
	if err != nil {
		return err
	}
	base := filepath.Join(root, "brokers", "github", "internal", "upstream")
	pinned, err := runtime.loadPinned(filepath.Join(base, "snapshots"))
	if err != nil {
		return fmt.Errorf("load reviewed GitHub snapshots: %w", err)
	}
	query, err := os.ReadFile(filepath.Join(base, "graphql-introspection.graphql"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), runtime.timeout)
	defer cancel()
	current, err := runtime.fetchCurrent(ctx, query)
	if err != nil {
		return err
	}
	report, err := upstreamdrift.Analyze(pinned, current)
	if err != nil {
		return err
	}
	if err := writeReport(runtime.stdout, options.outputPath, report); err != nil {
		return err
	}
	status := "clean\n"
	if report.HasDrift() {
		status = "drift\n"
	}
	return writeOptional(options.statusPath, []byte(status), 0o600)
}

type checkOptions struct {
	outputPath string
	statusPath string
}

func parseOptions(args []string) (checkOptions, error) {
	var outputPath, statusPath string
	flags := flag.NewFlagSet("check-github-drift", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&outputPath, "output", "", "write the Markdown report to this path")
	flags.StringVar(&statusPath, "status-output", "", "write clean or drift to this path")
	if err := flags.Parse(args); err != nil {
		return checkOptions{}, err
	}
	return checkOptions{outputPath: outputPath, statusPath: statusPath}, nil
}

func fetchCurrentFromGitHub(ctx context.Context, query []byte) (upstreamdrift.SnapshotSet, error) {
	return upstreamdrift.NewClient(os.Getenv("GITHUB_TOKEN")).FetchCurrent(ctx, query)
}

func writeReport(stdout io.Writer, path string, report upstreamdrift.Report) error {
	if path == "" {
		return upstreamdrift.WriteMarkdown(stdout, report)
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- operator-selected output is intentional.
	if err != nil {
		return err
	}
	writeErr := upstreamdrift.WriteMarkdown(file, report)
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr)
}

func writeOptional(path string, data []byte, mode os.FileMode) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, mode) // #nosec G306,G304 -- operator-selected status output is intentional and private.
}

func repositoryRoot() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", io.EOF
		}
		directory = parent
	}
}
