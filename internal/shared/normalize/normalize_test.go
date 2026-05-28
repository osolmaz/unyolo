package normalize

import "testing"

func TestStringsTrimsDropsEmptyValuesAndDeduplicates(t *testing.T) {
	t.Parallel()
	got := Strings([]string{" a ", "", "a", "b"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("Strings() = %#v, want a,b", got)
	}
}
