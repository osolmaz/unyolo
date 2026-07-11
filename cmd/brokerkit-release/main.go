package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/osolmaz/brokerkit/tooling/release"
)

func main() {
	broker := flag.String("broker", "", "broker binary and asset prefix")
	command := flag.String("command", "", "Go main package")
	version := flag.String("version", "", "embedded release version")
	directory := flag.String("directory", ".", "repository root")
	dist := flag.String("dist", "", "release output directory")
	flag.Parse()
	if *dist == "" {
		*dist = filepath.Join(*directory, "dist")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := release.Run(ctx, release.Options{Directory: *directory, Broker: *broker, Command: *command, Version: *version, Dist: *dist}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("Release assets written to %s\n", *dist)
}
