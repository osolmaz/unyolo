package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/osolmaz/unyolo/internal/tooling/release"
)

func main() {
	broker := flag.String("broker", "", "broker binary and asset prefix")
	command := flag.String("command", "", "Go main package")
	version := flag.String("version", "", "embedded release version")
	directory := flag.String("directory", ".", "repository root")
	dist := flag.String("dist", "", "release output directory")
	extras := extraCommands{}
	targets := releaseTargets{}
	flag.Var(&extras, "extra-command", "companion binary and Go package as name=package; repeat as needed")
	flag.Var(&targets, "target", "native release target as os/arch; defaults to the host target")
	flag.Parse()
	if *dist == "" {
		*dist = filepath.Join(*directory, "dist")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := release.Run(ctx, release.Options{Directory: *directory, Broker: *broker, Command: *command, Version: *version, Dist: *dist, ExtraCommands: extras, Targets: targets}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("Release assets written to %s\n", *dist)
}

type releaseTargets []release.Target

func (values releaseTargets) String() string {
	parts := make([]string, 0, len(values))
	for _, target := range values {
		parts = append(parts, target.String())
	}
	return strings.Join(parts, ",")
}

func (values *releaseTargets) Set(value string) error {
	target, err := release.ParseTarget(value)
	if err != nil {
		return err
	}
	*values = append(*values, target)
	return nil
}

type extraCommands map[string]string

func (values extraCommands) String() string {
	parts := make([]string, 0, len(values))
	for name, command := range values {
		parts = append(parts, name+"="+command)
	}
	return strings.Join(parts, ",")
}

func (values extraCommands) Set(value string) error {
	name, command, ok := strings.Cut(value, "=")
	if !ok || name == "" || command == "" {
		return fmt.Errorf("extra command must use name=package")
	}
	if _, exists := values[name]; exists {
		return fmt.Errorf("extra command %q is duplicated", name)
	}
	values[name] = command
	return nil
}
