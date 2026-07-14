package sortedlookup

import "testing"

func TestString(t *testing.T) {
	t.Parallel()
	values := []struct{ Name string }{{Name: "a"}, {Name: "b"}}
	if value, found := String(values, "b", func(value struct{ Name string }) string { return value.Name }); !found || value.Name != "b" {
		t.Fatalf("String() = %+v, %t", value, found)
	}
	if _, found := String(values, "c", func(value struct{ Name string }) string { return value.Name }); found {
		t.Fatal("String() found an absent value")
	}
	loader := func() ([]struct{ Name string }, error) { return values, nil }
	if value, found := LoadString(loader, "a", func(value struct{ Name string }) string { return value.Name }); !found || value.Name != "a" {
		t.Fatalf("LoadString() = %+v, %t", value, found)
	}
}
