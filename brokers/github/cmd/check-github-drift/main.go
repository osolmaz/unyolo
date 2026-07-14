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
	var outputPath, statusPath string
	flag.StringVar(&outputPath, "output", "", "write the Markdown report to this path")
	flag.StringVar(&statusPath, "status-output", "", "write clean or drift to this path")
	flag.Parse()
	root, err := repositoryRoot()
	if err != nil {
		return err
	}
	base := filepath.Join(root, "brokers", "github", "internal", "upstream")
	pinned, err := upstreamdrift.LoadPinned(filepath.Join(base, "snapshots"))
	if err != nil {
		return fmt.Errorf("load reviewed GitHub snapshots: %w", err)
	}
	query, err := os.ReadFile(filepath.Join(base, "graphql-introspection.graphql"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	current, err := upstreamdrift.NewClient(os.Getenv("GITHUB_TOKEN")).FetchCurrent(ctx, query)
	if err != nil {
		return err
	}
	report, err := upstreamdrift.Analyze(pinned, current)
	if err != nil {
		return err
	}
	if err := writeReport(outputPath, report); err != nil {
		return err
	}
	status := "clean\n"
	if report.HasDrift() {
		status = "drift\n"
	}
	return writeOptional(statusPath, []byte(status), 0o600)
}

func writeReport(path string, report upstreamdrift.Report) error {
	if path == "" {
		return upstreamdrift.WriteMarkdown(os.Stdout, report)
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
