package main

import (
	"context"
	"fmt"
	"os"

	"github.com/osolmaz/brokerkit/deployment/component"
	"github.com/osolmaz/brokerkit/internal/buildinfo"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		_, _ = fmt.Fprintln(os.Stdout, buildinfo.Version)
		return
	}
	if len(os.Args) != 2 || os.Args[1] != "setup-component" {
		os.Exit(64)
	}
	config := component.Config{
		ComponentID: "fake", ProfileAPI: "brokerkit.io/fake-deployment/v1",
		AllowedPaths:    []string{"/etc/brokerkit-e2e", "/var/lib/brokerkit-e2e"},
		AllowedAccounts: []string{"brokerkit-e2e"},
		AllowedGroups:   []string{"brokerkit-e2e", "brokerkit-e2e-agent"},
		BackupDirectory: "/var/lib/brokerkit-e2e/backups",
	}
	if err := component.Serve(context.Background(), os.Stdin, os.Stdout, config); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
