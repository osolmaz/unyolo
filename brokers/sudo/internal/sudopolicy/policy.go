// Package sudopolicy defines sudo-broker's provider-owned policy vocabulary.
package sudopolicy

import (
	"sort"

	corepolicy "github.com/osolmaz/brokerkit/authorization/policy"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
)

const (
	OperationExecCommand = "exec.command"
	TargetUser           = "user"
	TargetName           = "name"
	AttrCommandID        = "command_id"
	ArgumentPrefix       = "argument."
)

func Registry(snapshot *catalog.Snapshot) corepolicy.Registry {
	attrs := map[string]corepolicy.AttrSpec{AttrCommandID: {}}
	for _, slot := range snapshot.SlotNames() {
		attrs[ArgumentPrefix+slot] = corepolicy.AttrSpec{}
	}
	attributeNames := make([]string, 0, len(attrs))
	for name := range attrs {
		attributeNames = append(attributeNames, name)
	}
	sort.Strings(attributeNames)
	return corepolicy.Registry{
		Operations: map[string]corepolicy.OperationSpec{
			OperationExecCommand: {TargetKinds: []string{TargetUser}, Attrs: attributeNames, Grantable: true, GrantMode: corepolicy.GrantModeExecution},
		},
		Targets: map[string]corepolicy.TargetSpec{
			TargetUser: {Fields: map[string]corepolicy.FieldSpec{TargetName: {Required: true}}},
		},
		Attrs: attrs,
	}
}

func Request(client string, resolved catalog.Resolved) corepolicy.Request {
	attrs := map[string][]string{AttrCommandID: {resolved.CommandID}}
	for name, value := range resolved.SlotValues {
		attrs[ArgumentPrefix+name] = []string{value}
	}
	return corepolicy.Request{
		Client: client, Operation: OperationExecCommand,
		Target: corepolicy.Target{Kind: TargetUser, Fields: map[string][]string{TargetName: {resolved.TargetUser}}},
		Attrs:  attrs,
	}
}
