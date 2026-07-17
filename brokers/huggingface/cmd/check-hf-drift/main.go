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

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/upstreamdrift"
)

const pinnedSnapshot = "brokers/huggingface/internal/opbinding/hf-openapi-2026-07-13.json"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	client := upstreamdrift.NewClient()
	return runWith(runtime{
		args:    os.Args[1:],
		stdout:  os.Stdout,
		timeout: 5 * time.Minute,
		root:    repositoryRoot,
		fetch:   client.FetchCurrent,
	})
}

type runtime struct {
	args    []string
	stdout  io.Writer
	timeout time.Duration
	root    func() (string, error)
	fetch   func(context.Context) ([]byte, upstreamdrift.Source, error)
}

func runWith(value runtime) error {
	options, err := parseOptions(value.args)
	if err != nil {
		return err
	}
	report, err := buildReport(value)
	if err != nil {
		return err
	}
	if err := writeReport(value.stdout, options.outputPath, report); err != nil {
		return err
	}
	status := []byte("clean\n")
	if report.HasDrift() {
		status = []byte("drift\n")
	}
	return writeOptional(options.statusPath, status)
}

func buildReport(value runtime) (upstreamdrift.Report, error) {
	root, err := value.root()
	if err != nil {
		return upstreamdrift.Report{}, err
	}
	pinned, err := os.ReadFile(filepath.Join(root, pinnedSnapshot)) // #nosec G304 -- root and suffix are fixed.
	if err != nil {
		return upstreamdrift.Report{}, fmt.Errorf("load reviewed Hugging Face OpenAPI snapshot: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), value.timeout)
	defer cancel()
	current, source, err := value.fetch(ctx)
	if err != nil {
		return upstreamdrift.Report{}, err
	}
	return upstreamdrift.Analyze(pinned, current, source)
}

type options struct {
	outputPath string
	statusPath string
}

func parseOptions(args []string) (options, error) {
	var result options
	flags := flag.NewFlagSet("check-hf-drift", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&result.outputPath, "output", "", "write the Markdown report to this path")
	flags.StringVar(&result.statusPath, "status-output", "", "write clean or drift to this path")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	return result, nil
}

func writeReport(stdout io.Writer, path string, report upstreamdrift.Report) error {
	if path == "" {
		return upstreamdrift.WriteMarkdown(stdout, report)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- operator-selected output is intentional.
	if err != nil {
		return err
	}
	writeErr := upstreamdrift.WriteMarkdown(file, report)
	return errors.Join(writeErr, file.Close())
}

func writeOptional(path string, data []byte) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600) // #nosec G304,G306 -- operator-selected private output is intentional.
}

func repositoryRoot() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return findRepositoryRoot(directory)
}

func findRepositoryRoot(directory string) (string, error) {
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
