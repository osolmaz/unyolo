package policy

import (
	"slices"

	corepolicy "github.com/osolmaz/brokerkit/policy"
)

func registry() corepolicy.Registry {
	specs := operationSpecs()
	operations := make(map[string]corepolicy.OperationSpec, len(specs))
	for op, spec := range specs {
		operations[string(op)] = spec
	}
	return corepolicy.Registry{
		Operations: operations,
		Targets: map[string]corepolicy.TargetSpec{
			"repo": {
				Fields: map[string]corepolicy.FieldSpec{
					"owner": {Required: true},
					"name":  {Required: true},
				},
			},
			"installation": {},
		},
		Attrs: map[string]corepolicy.AttrSpec{
			"ref":      {},
			"base_ref": {},
			"head_ref": {},
			"path":     {},
		},
	}
}

func operationSpecs() map[Operation]corepolicy.OperationSpec {
	return map[Operation]corepolicy.OperationSpec{
		OperationGitFetch:              {TargetKinds: []string{"repo"}},
		OperationGitPushAdvertise:      {TargetKinds: []string{"repo"}},
		OperationGitPushBranchCreate:   {TargetKinds: []string{"repo"}, Attrs: []string{"ref"}, Grantable: true},
		OperationGitPushFastForward:    {TargetKinds: []string{"repo"}, Attrs: []string{"ref"}, Grantable: true},
		OperationGitPushForce:          {TargetKinds: []string{"repo"}, Attrs: []string{"ref"}, Grantable: true},
		OperationGitRefDelete:          {TargetKinds: []string{"repo"}, Attrs: []string{"ref"}, Grantable: true},
		OperationGitTagUpdate:          {TargetKinds: []string{"repo"}, Attrs: []string{"ref"}, Grantable: true},
		OperationPullRequestCreate:     {TargetKinds: []string{"repo"}, Attrs: []string{"ref", "base_ref", "head_ref"}, Grantable: true},
		OperationPullRequestUpdate:     {TargetKinds: []string{"repo"}, Attrs: []string{"ref", "base_ref", "head_ref"}, Grantable: true},
		OperationPullRequestMerge:      {TargetKinds: []string{"repo"}, Attrs: []string{"ref", "base_ref", "head_ref"}, Grantable: true},
		OperationChecksRead:            {TargetKinds: []string{"repo"}},
		OperationRepoMetadataRead:      {TargetKinds: []string{"repo"}},
		OperationContentsRead:          {TargetKinds: []string{"repo"}, Attrs: []string{"ref", "path"}},
		OperationInstallationReposList: {TargetKinds: []string{"installation"}},
		OperationWebhookGitHubReceive:  {TargetKinds: []string{"repo"}},
	}
}

func allOperations() []Operation {
	ops := make([]Operation, 0, len(operationSpecs()))
	for op := range operationSpecs() {
		ops = append(ops, op)
	}
	slices.Sort(ops)
	return ops
}

func operationAttrs(op Operation) []string {
	return operationSpecs()[op].Attrs
}

func targetKindForOperation(op Operation) string {
	if slices.Contains(operationSpecs()[op].TargetKinds, "installation") {
		return "installation"
	}
	return "repo"
}

// mutate4go-manifest-begin
// {"version":1,"tested_at":"2026-07-09T22:59:21+08:00","module_hash":"11e593f41d5c917eddf9c6c967592a0f9b19b985f1814bb28eadf316ed9a1b70","functions":[{"id":"func/registry","name":"registry","line":9,"end_line":33,"hash":"885670fa4d5a1b8dac48306857567171383a6ae8399ccb8cc473ffc90cee3fad"},{"id":"func/operationSpecs","name":"operationSpecs","line":35,"end_line":53,"hash":"57f7142db32ebeea64ef727d6be9102481d271e21382c8ec05cdfb32e4f407e2"},{"id":"func/allOperations","name":"allOperations","line":55,"end_line":62,"hash":"c482dde499afc2b44e8cc21367178cf24e895b39a22afa157dba6921ff77aa6f"},{"id":"func/operationAttrs","name":"operationAttrs","line":64,"end_line":66,"hash":"701f51a32057ce9e4f0d7aa49d515af3a891e75118a36dbf1b9b7a06491d6b2f"},{"id":"func/targetKindForOperation","name":"targetKindForOperation","line":68,"end_line":73,"hash":"141b4bad3c04987c73ef84b887cf9a8f637740b4c8647d11095d7251fc81bdcf"}]}
// mutate4go-manifest-end
