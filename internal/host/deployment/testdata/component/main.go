package main

import (
	"context"
	"fmt"
	"os"

	"github.com/osolmaz/unyolo/deployment/component"
	"github.com/osolmaz/unyolo/internal/buildinfo"
	clientconfig "github.com/osolmaz/unyolo/internal/config/client"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		_, _ = fmt.Fprintln(os.Stdout, buildinfo.Version)
		return
	}
	if len(os.Args) == 5 && os.Args[1] == "setup-component-probe" {
		if _, err := clientconfig.Read(os.Args[2], os.Args[3], os.Args[4]); err != nil {
			os.Exit(1)
		}
		_, _ = fmt.Fprintln(os.Stdout, "ok")
		return
	}
	if len(os.Args) != 2 || os.Args[1] != "setup-component" {
		os.Exit(64)
	}
	config := component.Config{
		ComponentID: "fake", ProfileAPI: "unyolo.io/fake-deployment/v1",
		AllowedPaths:    []string{"/etc/unyolo-e2e", "/var/lib/unyolo-e2e", "/proc/unyolo-e2e"},
		AllowedAccounts: []string{"unyolo-e2e"},
		AllowedGroups:   []string{"unyolo-e2e", "unyolo-e2e-agent"},
		BackupDirectory: "/var/lib/unyolo-e2e/backups",
	}
	if err := component.Serve(context.Background(), os.Stdin, os.Stdout, config); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
