package clientconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOperatorDocumentRoundTrip(t *testing.T) {
	home := t.TempDir()
	value := Operator{Endpoint: "unix:///run/unyolo/github/operator/broker.sock", Secret: strings.Repeat("s", 43)}
	path, err := WriteOperatorForHomeOwner(home, "gh-broker", value)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(home, ".config", "gh-broker", "operator.json") {
		t.Fatalf("path = %q", path)
	}
	loaded, err := ReadOperatorPath(path, os.Getuid())
	if err != nil || loaded != value {
		t.Fatalf("ReadOperatorPath() = %#v, %v", loaded, err)
	}
	if _, err := ReadOperatorPath(path, os.Getuid()+1); err == nil {
		t.Fatal("operator client owned by another account was accepted")
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadOperatorPath(path, os.Getuid()); err == nil {
		t.Fatal("group-readable operator client was accepted")
	}
}

func TestOperatorDocumentRejectsInvalidValues(t *testing.T) {
	valid := Operator{Endpoint: "tcp://127.0.0.1:9000", Secret: strings.Repeat("s", 43)}
	if _, err := RenderOperator(valid); err != nil {
		t.Fatalf("loopback operator endpoint was rejected: %v", err)
	}
	for name, value := range map[string]Operator{
		"remote endpoint": {Endpoint: "tcp://192.0.2.1:9000", Secret: valid.Secret},
		"bad endpoint":    {Endpoint: "broker.sock", Secret: valid.Secret},
		"empty secret":    {Endpoint: valid.Endpoint},
		"padded secret":   {Endpoint: valid.Endpoint, Secret: valid.Secret + "\n"},
	} {
		if _, err := RenderOperator(value); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	if _, err := OperatorPath("relative", "gh-broker"); err == nil {
		t.Fatal("relative home was accepted")
	}
	if _, err := WriteOperatorForHomeOwner(t.TempDir(), "gh-broker", Operator{}); err == nil {
		t.Fatal("invalid operator client was written")
	}
}

func TestReadOperatorPathRejectsInvalidFiles(t *testing.T) {
	directory := t.TempDir()
	write := func(name, data string) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for name, path := range map[string]string{
		"relative":    "operator.json",
		"missing":     filepath.Join(directory, "missing.json"),
		"wrong api":   write("api.json", `{"api_version":"unyolo.io/client/v1","operator_endpoint":"tcp://127.0.0.1:1","shared_secret":"secret"}`),
		"unknown key": write("unknown.json", `{"api_version":"unyolo.io/operator-client/v1","operator_endpoint":"tcp://127.0.0.1:1","shared_secret":"secret","extra":1}`),
		"bad value":   write("value.json", `{"api_version":"unyolo.io/operator-client/v1","operator_endpoint":"tcp://192.0.2.1:1","shared_secret":"secret"}`),
		"too large":   write("large.json", strings.Repeat(" ", maxClientConfigBytes+1)),
	} {
		if _, err := ReadOperatorPath(path, os.Getuid()); err == nil {
			t.Fatalf("%s operator client was accepted", name)
		}
	}
}
