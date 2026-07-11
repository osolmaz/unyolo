package strictjson

import "testing"

func TestRejectDuplicateKeys(t *testing.T) {
	t.Parallel()
	for _, value := range []string{`{"a":1,"a":2}`, `{"a":{"b":1,"b":2}}`, `[{"a":1,"a":2}]`} {
		if err := RejectDuplicateKeys([]byte(value)); err == nil {
			t.Fatalf("accepted %s", value)
		}
	}
	for _, value := range []string{`{"a":1,"b":{"a":2}}`, `[1,true,null,"x"]`} {
		if err := RejectDuplicateKeys([]byte(value)); err != nil {
			t.Fatalf("rejected %s: %v", value, err)
		}
	}
}

func TestRejectDuplicateKeysRejectsMalformedAndTrailingJSON(t *testing.T) {
	t.Parallel()
	for _, value := range []string{`{`, `{"a":1} {}`, ``} {
		if err := RejectDuplicateKeys([]byte(value)); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}
