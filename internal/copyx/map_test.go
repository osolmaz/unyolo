package copyx

import "testing"

func TestStringMap(t *testing.T) {
	if got := StringMap(nil); got != nil {
		t.Fatalf("StringMap(nil) = %+v, want nil", got)
	}
	source := map[string]string{"a": "b"}
	copied := StringMap(source)
	copied["a"] = "changed"
	if source["a"] != "b" {
		t.Fatalf("StringMap returned alias, source = %+v", source)
	}
}
