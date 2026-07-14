package copyx

import (
	"slices"
	"testing"
)

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

func TestJSONMap(t *testing.T) {
	source := map[string]any{"nested": map[string]any{"value": "original"}}
	copied := JSONMap(source)
	copied["nested"].(map[string]any)["value"] = "changed"
	if source["nested"].(map[string]any)["value"] != "original" {
		t.Fatal("JSONMap returned a nested alias")
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

func TestCanonicalStringSliceMap(t *testing.T) {
	source := map[string][]string{"refs": {"dev", "main", "dev"}}
	got := CanonicalStringSliceMap(source)
	if !slices.Equal(got["refs"], []string{"dev", "main"}) {
		t.Fatalf("CanonicalStringSliceMap() = %+v", got)
	}
	if !slices.Equal(source["refs"], []string{"dev", "main", "dev"}) {
		t.Fatalf("CanonicalStringSliceMap() mutated source = %+v", source)
	}
	if !StringSliceMapsEqual(source, map[string][]string{"refs": {"main", "dev"}}) {
		t.Fatal("StringSliceMapsEqual() = false for equivalent sets")
	}
	if StringSliceMapsEqual(source, map[string][]string{"refs": {"other"}}) {
		t.Fatal("StringSliceMapsEqual() = true for different sets")
	}
	if !StringSlicesEqual([]string{"dev", "main", "dev"}, []string{"main", "dev"}) {
		t.Fatal("StringSlicesEqual() = false for equivalent sets")
	}
	if StringSlicesEqual([]string{"dev"}, []string{"main"}) {
		t.Fatal("StringSlicesEqual() = true for different sets")
	}
}
