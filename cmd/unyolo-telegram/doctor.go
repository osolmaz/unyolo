package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	operatorv1 "github.com/osolmaz/unyolo/operator/v1"
	"github.com/osolmaz/unyolo/protocol/contract"
)

// doctorCheck is one line of the doctor report.
type doctorCheck struct {
	name   string
	ok     bool
	detail string
}

// runDoctor reports whether this host's Telegram owner can work: its
// configuration, whether another process owns the bot, and every broker route.
// Run it as the unyolo-telegram account, which owns the credentials. It never
// polls the bot, so it does not take updates away from the running owner.
func runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("unyolo-telegram doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "/etc/unyolo-telegram/config.json", "absolute owner config path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("doctor does not accept positional arguments")
	}
	checks := doctorChecks(ctx, *configPath)
	failed := false
	for _, check := range checks {
		status := "ok  "
		if !check.ok {
			status, failed = "FAIL", true
		}
		if _, err := fmt.Fprintf(stdout, "%s %s: %s\n", status, check.name, check.detail); err != nil {
			return err
		}
	}
	if failed {
		return errors.New("unyolo-telegram doctor found problems")
	}
	return nil
}

func doctorChecks(ctx context.Context, path string) []doctorCheck {
	cfg, err := loadIngressConfig(path)
	if err != nil {
		return []doctorCheck{{name: "config", detail: err.Error()}}
	}
	checks := []doctorCheck{{name: "config", ok: true, detail: path}}
	checks = append(checks, botCheck(ctx, cfg), ownerConflictCheck(cfg))
	return append(checks, routeChecks(ctx, cfg)...)
}

func botCheck(ctx context.Context, cfg ingressConfig) doctorCheck {
	check := doctorCheck{name: "bot"}
	client, err := newTelegramClient(cfg)
	if err != nil {
		check.detail = err.Error()
		return check
	}
	webhook, err := client.HasWebhook(ctx)
	switch {
	case err != nil:
		check.detail = err.Error()
	case webhook:
		check.detail = "the bot delivers its updates to a webhook, so another process owns it"
	default:
		check.ok, check.detail = true, "reachable, no webhook"
	}
	return check
}

func ownerConflictCheck(cfg ingressConfig) doctorCheck {
	data, err := readBoundedFile(ownerConflictPath(cfg), 128)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return doctorCheck{name: "owner", ok: true, detail: "no other process received this bot's updates"}
	case err != nil:
		return doctorCheck{name: "owner", detail: "read owner conflict record: " + err.Error()}
	default:
		return doctorCheck{name: "owner", detail: "another process received this bot's updates at " + strings.TrimSpace(string(data)) +
			"; stop every other program that uses this bot token"}
	}
}

func routeChecks(ctx context.Context, cfg ingressConfig) []doctorCheck {
	routes := make([]string, 0, len(cfg.Routes))
	for route := range cfg.Routes {
		routes = append(routes, route)
	}
	slices.Sort(routes)
	checks := make([]doctorCheck, 0, len(routes))
	for _, route := range routes {
		checks = append(checks, routeCheck(ctx, route, cfg.Routes[route]))
	}
	return checks
}

func routeCheck(ctx context.Context, route string, source routeConfig) doctorCheck {
	check := doctorCheck{name: "route " + route}
	sources, err := routeSources(ingressConfig{Routes: map[string]routeConfig{route: source}})
	if err != nil {
		check.detail = err.Error()
		return check
	}
	descriptor, err := sources[route].Discover(ctx)
	switch {
	case err != nil:
		check.detail = err.Error()
	case !currentContract(descriptor):
		check.detail = "the broker does not serve the current Operator V1 contract"
	default:
		check.ok, check.detail = true, "broker build "+descriptor.BuildID
	}
	return check
}

func currentContract(descriptor operatorv1.Descriptor) bool {
	return descriptor.APIVersion == operatorv1.APIVersion && descriptor.ContractDigest == contract.OperatorV1Digest
}
