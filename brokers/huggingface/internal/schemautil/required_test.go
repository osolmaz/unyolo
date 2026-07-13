package schemautil

import (
	"reflect"
	"testing"
)

func TestRemoveRequiredProperty(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   map[string]any
		want map[string]any
	}{
		{
			name: "removes one requirement",
			in:   map[string]any{"required": []any{"name", "token"}},
			want: map[string]any{"required": []any{"name"}},
		},
		{
			name: "removes empty requirement list",
			in:   map[string]any{"required": []any{"token"}},
			want: map[string]any{},
		},
		{
			name: "ignores unsupported representation",
			in:   map[string]any{"required": []string{"token"}},
			want: map[string]any{"required": []string{"token"}},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			RemoveRequiredProperty(test.in, "token")
			if !reflect.DeepEqual(test.in, test.want) {
				t.Fatalf("RemoveRequiredProperty() = %#v, want %#v", test.in, test.want)
			}
		})
	}
}
