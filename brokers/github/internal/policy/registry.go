package policy

import (
	"slices"
	"strings"

	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	corepolicy "github.com/osolmaz/brokerkit/policy"
)

type operationInfo struct {
	spec              corepolicy.OperationSpec
	familyGlobAllowed bool
}

func registry() corepolicy.Registry {
	value, err := CatalogRegistry()
	if err != nil {
		panic(err)
	}
	return value
}

func operationSpecs() map[Operation]corepolicy.OperationSpec {
	result := make(map[Operation]corepolicy.OperationSpec, len(opcatalog.MustAll()))
	for op, info := range operationInfos() {
		result[op] = info.spec
	}
	return result
}

func operationInfos() map[Operation]operationInfo {
	descriptors := opcatalog.MustAll()
	result := make(map[Operation]operationInfo, len(descriptors))
	for _, descriptor := range descriptors {
		if !descriptor.AgentFacing {
			continue
		}
		mode := corepolicy.GrantModeWindow
		if descriptor.AuthorizationMode == opcatalog.ModeExecution {
			mode = corepolicy.GrantModeExecution
		}
		result[Operation(descriptor.Name)] = operationInfo{
			spec: corepolicy.OperationSpec{
				TargetKinds: []string{descriptor.TargetKind},
				Attrs:       CatalogAttributeNames(),
				Grantable:   true,
				GrantMode:   mode,
			},
			familyGlobAllowed: descriptor.FamilyGlobAllowed,
		}
	}
	for operation, spec := range protocolOperationSpecs() {
		result[operation] = operationInfo{spec: spec, familyGlobAllowed: true}
	}
	return result
}

func allOperations() []Operation {
	ops := make([]Operation, 0, len(operationInfos()))
	for op := range operationInfos() {
		ops = append(ops, op)
	}
	slices.Sort(ops)
	return ops
}

func operationAttrs(op Operation) []string {
	return slices.Clone(operationInfos()[canonicalOperation(op)].spec.Attrs)
}

func targetKindForOperation(op Operation) string {
	spec := operationInfos()[canonicalOperation(op)].spec
	if len(spec.TargetKinds) == 0 {
		return ""
	}
	return spec.TargetKinds[0]
}

func expandFamilyOperation(op Operation) ([]Operation, bool) {
	text := string(canonicalOperation(op))
	if !strings.HasSuffix(text, ".*") {
		return nil, false
	}
	prefix := strings.TrimSuffix(text, "*")
	out := []Operation{}
	for name, info := range operationInfos() {
		if info.familyGlobAllowed && strings.HasPrefix(string(name), prefix) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out, len(out) > 0
}

func canonicalOperation(op Operation) Operation {
	return Operation(strings.TrimSpace(string(op)))
}

// mutate4go-manifest-begin
// {"version":1,"tested_at":"2026-07-09T22:59:21+08:00","module_hash":"11e593f41d5c917eddf9c6c967592a0f9b19b985f1814bb28eadf316ed9a1b70","functions":[{"id":"func/registry","name":"registry","line":9,"end_line":33,"hash":"885670fa4d5a1b8dac48306857567171383a6ae8399ccb8cc473ffc90cee3fad"},{"id":"func/operationSpecs","name":"operationSpecs","line":35,"end_line":53,"hash":"57f7142db32ebeea64ef727d6be9102481d271e21382c8ec05cdfb32e4f407e2"},{"id":"func/allOperations","name":"allOperations","line":55,"end_line":62,"hash":"c482dde499afc2b44e8cc21367178cf24e895b39a22afa157dba6921ff77aa6f"},{"id":"func/operationAttrs","name":"operationAttrs","line":64,"end_line":66,"hash":"701f51a32057ce9e4f0d7aa49d515af3a891e75118a36dbf1b9b7a06491d6b2f"},{"id":"func/targetKindForOperation","name":"targetKindForOperation","line":68,"end_line":73,"hash":"141b4bad3c04987c73ef84b887cf9a8f637740b4c8647d11095d7251fc81bdcf"}]}
// mutate4go-manifest-end
