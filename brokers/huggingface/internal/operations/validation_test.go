package operations

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
)

func TestRepositoryAndContentValidationCorpus(t *testing.T) {
	validTarget := repositoryTarget{Kind: "repo", Type: "dataset", Owner: "acme", Name: "demo"}
	if !validRepositoryTarget(validTarget) || validRepositoryTarget(repositoryTarget{Kind: "repo", Type: "dataset", Owner: "../acme", Name: "demo"}) {
		t.Fatal("repository target validation mismatch")
	}
	for _, test := range []struct {
		target    repositoryTarget
		arguments repoCreateArguments
		valid     bool
	}{
		{validTarget, repoCreateArguments{Visibility: "private"}, true},
		{validTarget, repoCreateArguments{Visibility: "protected"}, false},
		{repositoryTarget{Type: "space"}, repoCreateArguments{Visibility: "protected", SDK: "docker"}, true},
		{repositoryTarget{Type: "space"}, repoCreateArguments{Visibility: "public", SDK: "unknown"}, false},
	} {
		if validRepoCreateArguments(test.target, test.arguments) != test.valid {
			t.Errorf("validRepoCreateArguments(%+v, %+v) mismatch", test.target, test.arguments)
		}
	}
	for _, metadata := range []struct{ summary, description, parent string }{
		{"", "", ""},
		{"ok", strings.Repeat("x", 10_001), ""},
		{"ok", "", "short"},
		{"ok", "", "zzzzzzz"},
	} {
		if validateCommitMetadata(metadata.summary, metadata.description, metadata.parent) == nil {
			t.Errorf("invalid commit metadata accepted: %+v", metadata)
		}
	}
	if validateCommitMetadata("update", "description", strings.Repeat("a", 40)) != nil {
		t.Fatal("valid commit metadata rejected")
	}
	content := base64.StdEncoding.EncodeToString([]byte("data"))
	oid := strings.Repeat("a", 64)
	size := int64(4)
	validOperations := []normalizedCommitOperation{
		{Kind: "file", Path: "file.txt", ContentBase64: &content},
		{Kind: "lfs_file", Path: "large.bin", OID: &oid, Size: &size},
		{Kind: "deleted_file", Path: "old.txt"},
		{Kind: "deleted_folder", Path: "old/"},
	}
	if operations, err := toCommitOperations(validOperations); err != nil || len(operations) != 4 {
		t.Fatalf("toCommitOperations() = %+v, %v", operations, err)
	}
	invalidOperations := [][]normalizedCommitOperation{
		{{Kind: "file", Path: "file.txt"}},
		{{Kind: "lfs_file", Path: "large.bin", ContentBase64: &content}},
		{{Kind: "deleted_file", Path: "old.txt", OID: &oid}},
		{{Kind: "unknown", Path: "file"}},
	}
	for _, values := range invalidOperations {
		if _, err := toCommitOperations(values); err == nil {
			t.Errorf("invalid commit operation accepted: %+v", values)
		}
	}
	if validateCopyArguments(fileCopyArguments{SourceType: "model", SourceOwner: "acme", SourceName: "source", SourceRevision: "main", SourcePath: "src.txt", Path: "dst.txt", Summary: "copy"}) != nil {
		t.Fatal("valid copy arguments rejected")
	}
	if validateCopyArguments(fileCopyArguments{SourceType: "shell", SourceOwner: "acme", SourceName: "source", SourceRevision: "main", SourcePath: "src.txt", Path: "dst.txt", Summary: "copy"}) == nil {
		t.Fatal("invalid copy source accepted")
	}
}

func TestSandboxValidationCorpus(t *testing.T) {
	dedicated := sandboxTarget{Kind: "sandbox", Namespace: "acme", Name: "review"}
	pooled := sandboxTarget{Kind: "sandbox", Namespace: "acme", Name: "review", Pool: "workers"}
	idleTooShort := 1
	validCreate := sandboxCreatePublic{Image: "python:3.12", Flavor: "cpu-basic", Environment: map[string]string{"MODE": "test"}}
	if err := validateSandboxCreatePublic(dedicated, validCreate); err != nil {
		t.Fatal(err)
	}
	invalidCreates := []struct {
		target sandboxTarget
		value  sandboxCreatePublic
	}{
		{dedicated, sandboxCreatePublic{}},
		{dedicated, sandboxCreatePublic{Image: "bad image", Flavor: "cpu-basic"}},
		{dedicated, sandboxCreatePublic{Image: "python:3.12", Flavor: "cpu-basic", IdleTimeoutSeconds: &idleTooShort}},
		{dedicated, sandboxCreatePublic{Image: "python:3.12", Flavor: "cpu-basic", Environment: map[string]string{"HF_TOKEN": "secret"}}},
		{dedicated, sandboxCreatePublic{Image: "python:3.12", Flavor: "cpu-basic", Volumes: []sandboxVolumeArgument{{Type: "shell", Source: "acme/data", MountPath: "/data"}}}},
		{pooled, validCreate},
	}
	for _, test := range invalidCreates {
		if validateSandboxCreatePublic(test.target, test.value) == nil {
			t.Errorf("invalid sandbox create accepted: %+v", test)
		}
	}
	if err := validateSandboxPoolCreatePublic(sandboxPoolCreatePublic{Image: "python:3.12", Flavor: "cpu-basic", SandboxesPerHost: 10, WarmUp: 1, MaxHosts: 2}); err != nil {
		t.Fatal(err)
	}
	for _, value := range []sandboxPoolCreatePublic{
		{Image: "bad image", Flavor: "cpu-basic", SandboxesPerHost: 10, WarmUp: 1, MaxHosts: 2},
		{Image: "python:3.12", Flavor: "cpu-basic", SandboxesPerHost: 0, WarmUp: 1, MaxHosts: 2},
		{Image: "python:3.12", Flavor: "cpu-basic", SandboxesPerHost: 10, WarmUp: 3, MaxHosts: 2},
	} {
		if validateSandboxPoolCreatePublic(value) == nil {
			t.Errorf("invalid pool configuration accepted: %+v", value)
		}
	}
	validCommand := sandboxCommandArguments{Argv: []string{"echo", "hi"}, MaxOutputBytes: 1024}
	if validateSandboxCommandArguments(validCommand) != nil {
		t.Fatal("valid sandbox command rejected")
	}
	for _, command := range []sandboxCommandArguments{
		{MaxOutputBytes: 1024},
		{Argv: []string{"echo"}, ShellCommand: "echo", MaxOutputBytes: 1024},
		{Argv: []string{""}, MaxOutputBytes: 1024},
		{Argv: []string{strings.Repeat("x", 1201)}, MaxOutputBytes: 1024},
		{Argv: []string{"echo"}, Environment: map[string]string{"BAD-KEY": "x"}, MaxOutputBytes: 1024},
	} {
		if validateSandboxCommandArguments(command) == nil {
			t.Errorf("invalid sandbox command accepted: %+v", command)
		}
	}
	if validateSandboxFileWrite(sandboxFileWriteArguments{Path: "/tmp/file", ContentBase64: "aGk=", Mode: "0644"}) != nil {
		t.Fatal("valid sandbox file rejected")
	}
	for _, value := range []sandboxFileWriteArguments{{Path: "", ContentBase64: "aGk="}, {Path: "/tmp/file", ContentBase64: "%%%"}, {Path: "/tmp/file", ContentBase64: "aGk=", Mode: "9999"}} {
		if validateSandboxFileWrite(value) == nil {
			t.Errorf("invalid sandbox file accepted: %+v", value)
		}
	}
	for _, entry := range []struct{ key, value string }{{"MODE", "test"}, {"_MODE2", "test"}} {
		if !validEnvironmentEntry(entry.key, entry.value) {
			t.Errorf("valid environment entry rejected: %+v", entry)
		}
	}
	for _, entry := range []struct{ key, value string }{{"", "x"}, {"1MODE", "x"}, {"BAD-KEY", "x"}, {"SBX_TOKEN", "x"}, {"MODE", "bad\x00value"}} {
		if validEnvironmentEntry(entry.key, entry.value) {
			t.Errorf("invalid environment entry accepted: %+v", entry)
		}
	}
	volume := sandboxVolumeArgument{Type: "bucket", Source: "acme/data", MountPath: "/data"}
	if got := volume.hubVolume(); got != (hubclient.SandboxVolume{Type: "bucket", Source: "acme/data", MountPath: "/data"}) {
		t.Fatalf("hubVolume() = %+v", got)
	}
}

func TestJSONHelpersRejectMalformedValues(t *testing.T) {
	var value map[string]any
	for _, raw := range []json.RawMessage{nil, json.RawMessage(`{"a":1,"a":2}`)} {
		if err := decodeClosed(raw, &value, maxTargetBytes); err == nil {
			t.Errorf("malformed JSON accepted: %s", raw)
		}
	}
	var empty emptyArguments
	if err := decodeClosed(json.RawMessage(`{"unknown":true}`), &empty, maxTargetBytes); err == nil {
		t.Fatal("unknown JSON field accepted")
	}
	if _, err := canonical(make(chan int)); err == nil {
		t.Fatal("unsupported canonical value accepted")
	}
}
