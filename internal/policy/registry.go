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
