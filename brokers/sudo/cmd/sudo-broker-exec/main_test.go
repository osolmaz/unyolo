package main

import "testing"

func TestParseOptions(t *testing.T) {
	t.Parallel()
	opts, err := parseOptions([]string{"--catalog", "/etc/sudo-broker/catalog.json", "--state", "/var/lib/sudo-broker/executions.json", "--socket", "/run/sudo-broker/helper.sock", "--broker-user", "sudo-broker"})
	if err != nil || opts.brokerUser != "sudo-broker" {
		t.Fatalf("parseOptions() = %+v, %v", opts, err)
	}
	if _, err := parseOptions(nil); err == nil {
		t.Fatal("empty options were accepted")
	}
}
