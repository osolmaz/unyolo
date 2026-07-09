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

func TestStringSliceMap(t *testing.T) {
	if got := StringSliceMap(nil); got != nil {
		t.Fatalf("StringSliceMap(nil) = %+v, want nil", got)
	}
	source := map[string][]string{"a": {"b"}}
	copied := StringSliceMap(source)
	copied["a"][0] = "changed"
	if source["a"][0] != "b" {
		t.Fatalf("StringSliceMap returned alias, source = %+v", source)
	}
}
