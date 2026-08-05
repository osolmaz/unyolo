package httpapi

import (
	"testing"

	"github.com/osolmaz/unyolo/brokers/huggingface/internal/opcatalog"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
)

// The OpenAI-compatible HTTP surface and the operation catalog must agree:
// every served inference route is an implemented native-protocol binding, and
// every native-protocol inference binding is one of the served routes.
func TestOpenAICompatibleRoutesMatchNativeProtocolCatalogBindings(t *testing.T) {
	servedOperations := map[string]string{
		"/v1/models":           "inference.models.list",
		"/v1/chat/completions": "inference.chat.complete",
	}
	for path, name := range servedOperations {
		if !isInferencePath(path) {
			t.Fatalf("%s is not served by the inference HTTP surface", path)
		}
		descriptor, found := opcatalog.ByName(name)
		if !found || descriptor.Implementation != opcatalog.StatusImplemented || descriptor.ExecutorKind != "native-protocol" {
			t.Fatalf("%s descriptor = %+v, found = %t", name, descriptor, found)
		}
	}
	for _, descriptor := range opcatalog.MustAll() {
		if descriptor.TargetKind != string(policy.KindInference) || descriptor.ExecutorKind != "native-protocol" {
			continue
		}
		if descriptor.Implementation != opcatalog.StatusImplemented {
			t.Fatalf("native-protocol inference operation %s is not implemented: %+v", descriptor.Name, descriptor)
		}
		if !servedOperation(servedOperations, descriptor.Name) {
			t.Fatalf("native-protocol inference operation %s has no served HTTP route", descriptor.Name)
		}
	}
}

func servedOperation(served map[string]string, name string) bool {
	for _, operation := range served {
		if operation == name {
			return true
		}
	}
	return false
}
