package catalog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAndResolveTypedCommand(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	artifact := filepath.Join(directory, "release.bin")
	if err := os.WriteFile(artifact, []byte("release"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := Parse([]byte(fmt.Sprintf(`{
		"version":1,
		"commands":[{
			"id":"deploy-release",
			"executable":"/usr/bin/printf",
			"arguments":[
				{"literal":"%%s:%%s:%%s"},
				{"slot":"environment","type":"enum","values":["staging","production"]},
				{"slot":"replicas","type":"integer","minimum":0,"maximum":20},
				{"slot":"artifact","type":"path_beneath","roots":[%q],"must_exist":true,"file_type":"regular"}
			],
			"target_users":["root"],
			"working_directory":%q,
			"timeout_seconds":30,
			"max_output_bytes":65536,
			"environment":{"SYSTEMD_COLORS":"0"},
			"description":"Deploy a reviewed release",
			"risk":"high"
		}]
	}`, directory, directory)))
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := snapshot.Resolve("deploy-release", "root", map[string]json.RawMessage{
		"environment": json.RawMessage(`"production"`), "replicas": json.RawMessage(`4`), "artifact": json.RawMessage(fmt.Sprintf(`%q`, artifact)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.CatalogDigest == "" || resolved.TargetUser != "root" || strings.Join(resolved.Arguments[1:], "|") != "%s:%s:%s|production|4|"+artifact {
		t.Fatalf("resolved = %+v", resolved)
	}
	command, ok := snapshot.Command("deploy-release")
	if !ok || command.Risk != "high" || command.Description == "" {
		t.Fatalf("command = %+v, %v", command, ok)
	}
	command.TargetUsers[0] = "nobody"
	again, _ := snapshot.Command("deploy-release")
	if again.TargetUsers[0] != "root" {
		t.Fatal("Command returned aliased data")
	}
}

func TestResolveRejectsArgumentEscapes(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	snapshot := mustParse(t, fmt.Sprintf(`{"version":1,"commands":[{
		"id":"inspect","executable":"/usr/bin/printf","arguments":[
			{"slot":"count","type":"integer","minimum":1,"maximum":3},
			{"slot":"kind","type":"enum","values":["safe"]},
			{"slot":"path","type":"path_beneath","roots":[%q],"must_exist":false,"file_type":"regular"}
		],"target_users":["root"],"working_directory":%q,"timeout_seconds":1,"max_output_bytes":0}]}`, directory, directory))
	tests := []map[string]json.RawMessage{
		{"count": json.RawMessage(`4`), "kind": json.RawMessage(`"safe"`), "path": json.RawMessage(`"/tmp/outside"`)},
		{"count": json.RawMessage(`1.0`), "kind": json.RawMessage(`"safe"`), "path": json.RawMessage(fmt.Sprintf(`%q`, filepath.Join(directory, "new")))},
		{"count": json.RawMessage(`1`), "kind": json.RawMessage(`"other"`), "path": json.RawMessage(fmt.Sprintf(`%q`, filepath.Join(directory, "new")))},
		{"count": json.RawMessage(`1`), "kind": json.RawMessage(`"safe"`), "path": json.RawMessage(fmt.Sprintf(`%q`, filepath.Join(directory, "new"))), "extra": json.RawMessage(`1`)},
	}
	for index, inputs := range tests {
		if _, err := snapshot.Resolve("inspect", "root", inputs); err == nil {
			t.Fatalf("case %d was accepted", index)
		}
	}
	if _, err := snapshot.Resolve("inspect", "nobody", nil); err == nil {
		t.Fatal("undeclared target user was accepted")
	}
}

func TestParseRejectsClosedSchemaAndUnsafeCatalogs(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	valid := fmt.Sprintf(`{"version":1,"commands":[{"id":"safe-id","executable":"/usr/bin/id","arguments":[],"target_users":["root"],"working_directory":%q,"timeout_seconds":1,"max_output_bytes":0}]}`, directory)
	tests := []string{
		strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(valid, `"timeout_seconds":1`, `"timeout_seconds":1,"unknown":true`, 1),
		strings.Replace(valid, `"safe-id"`, `"Bad_ID"`, 1),
		strings.Replace(valid, `"/usr/bin/id"`, `"/bin/sh"`, 1),
		strings.Replace(valid, `"target_users":["root"]`, `"target_users":["123"]`, 1),
		strings.Replace(valid, `"max_output_bytes":0`, `"max_output_bytes":1048577`, 1),
		strings.Replace(valid, `"arguments":[]`, `"arguments":[{"slot":"raw","type":"regex"}]`, 1),
		strings.Replace(valid, `"arguments":[]`, `"arguments":[{"literal":"ok","slot":"bad"}]`, 1),
		strings.Replace(valid, `"max_output_bytes":0`, `"max_output_bytes":0,"environment":{"LD_PRELOAD":"x"}`, 1),
	}
	for index, value := range tests {
		if _, err := Parse([]byte(value)); err == nil {
			t.Fatalf("case %d was accepted: %s", index, value)
		}
	}
	first := mustParse(t, valid)
	second := mustParse(t, valid)
	if first.Digest() == "" || first.Digest() != second.Digest() {
		t.Fatalf("digests = %q, %q", first.Digest(), second.Digest())
	}
}

func mustParse(t *testing.T, value string) *Snapshot {
	t.Helper()
	snapshot, err := Parse([]byte(value))
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
