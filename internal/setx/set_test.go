package setx

import "testing"

func TestAdd(t *testing.T) {
	values := make(map[string]struct{})
	if !Add(values, "value") || Add(values, "value") {
		t.Fatal("Add did not report first insertion and duplicate")
	}
}
