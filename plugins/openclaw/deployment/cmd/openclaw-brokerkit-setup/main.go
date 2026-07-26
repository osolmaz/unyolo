// Command openclaw-brokerkit-setup applies signed OpenClaw integration files.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/osolmaz/brokerkit/deployment/component"
)

var version = "dev"

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Fprintln(os.Stdout, version)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if len(os.Args) > 1 && os.Args[1] == "setup-component-probe" {
		if err := component.Probe(ctx, os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, "ok")
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "openclaw-brokerkit-setup does not accept arguments")
		os.Exit(64)
	}
	err := component.Serve(ctx, os.Stdin, os.Stdout, component.Config{
		ComponentID: "openclaw-brokerkit", ProfileAPI: "brokerkit.io/openclaw-deployment/v1",
		AllowedPaths:    []string{"/home", "/Users", "/var/lib/openclaw-brokerkit"},
		AllowedServices: []string{"openclaw.service"}, BackupDirectory: "/var/lib/openclaw-brokerkit/deployment-backups",
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
