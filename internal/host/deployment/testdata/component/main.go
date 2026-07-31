package main

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/osolmaz/unyolo/deployment/api"
	"github.com/osolmaz/unyolo/deployment/component"
	deploymentruntime "github.com/osolmaz/unyolo/deployment/runtime"
	"github.com/osolmaz/unyolo/internal/buildinfo"
	clientconfig "github.com/osolmaz/unyolo/internal/config/client"
	"golang.org/x/sys/unix"
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
	if err := serve(context.Background(), config); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(ctx context.Context, config component.Config) error {
	var request api.Request
	if err := deploymentruntime.ReadFrame(os.Stdin, &request); err != nil {
		return err
	}
	injectRollback := request.Action == api.ActionApply && hasRollbackCanary(request.Secrets)
	var applyInput, applyOutput bytes.Buffer
	if err := deploymentruntime.WriteFrame(&applyInput, request); err != nil {
		return err
	}
	if err := component.Serve(ctx, &applyInput, &applyOutput, config); err != nil {
		return err
	}
	var response api.Response
	if err := deploymentruntime.ReadFrame(&applyOutput, &response); err != nil {
		return err
	}
	if !injectRollback || response.Status != "applied" {
		return deploymentruntime.WriteFrame(os.Stdout, response)
	}
	rollbackRequest := request
	rollbackRequest.Action = api.ActionRollback
	rollbackRequest.Secrets = nil
	rollbackRequest.RollbackHandle = response.RollbackHandle
	var rollbackInput, rollbackOutput bytes.Buffer
	if err := deploymentruntime.WriteFrame(&rollbackInput, rollbackRequest); err != nil {
		return err
	}
	if err := component.Serve(ctx, &rollbackInput, &rollbackOutput, config); err != nil {
		return err
	}
	var rolledBack api.Response
	if err := deploymentruntime.ReadFrame(&rollbackOutput, &rolledBack); err != nil {
		return err
	}
	if rolledBack.Status != "rolled_back" {
		return fmt.Errorf("injected component rollback returned %q", rolledBack.Status)
	}
	response.Status = "rolled_back"
	response.RollbackHandle = ""
	response.BlockedReason = "component apply failed and was rolled back"
	return deploymentruntime.WriteFrame(os.Stdout, response)
}

func hasRollbackCanary(descriptors []api.SecretDescriptor) bool {
	const canary = "rollback-secret-canary"
	buffer := make([]byte, len(canary)+1)
	defer clear(buffer)
	for _, descriptor := range descriptors {
		count, err := unix.Pread(descriptor.FD, buffer, 0)
		if err == nil && count == len(canary) && string(buffer[:count]) == canary {
			return true
		}
	}
	return false
}
