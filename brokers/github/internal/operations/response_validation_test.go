package operations

import (
	"encoding/json"
	"testing"
)

func TestAgentOperationResultWrapsNonObjectProviderResults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "object", in: ` {"id":7} `, want: `{"id":7}`},
		{name: "array", in: `[{"number":42}]`, want: `{"items":[{"number":42}]}`},
		{name: "scalar", in: `true`, want: `{"value":true}`},
		{name: "null", in: `null`, want: `{"value":null}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := agentOperationResult(json.RawMessage(test.in))
			assertJSONEqual(t, got, test.want)
		})
	}
}
