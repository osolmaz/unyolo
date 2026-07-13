package strictjson

import (
	"strings"
	"testing"
)

func TestDecode(t *testing.T) {
	t.Parallel()
	type payload struct {
		Name string `json:"name"`
	}
	for _, test := range []struct {
		name   string
		value  string
		closed bool
	}{
		{name: "valid", value: `{"name":"alice"}`, closed: true},
		{name: "open schema", value: `{"name":"alice","future":true}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var got payload
			if err := Decode([]byte(test.value), &got, test.closed); err != nil || got.Name != "alice" {
				t.Fatalf("Decode() = %+v, %v", got, err)
			}
		})
	}
	for _, test := range []struct {
		name  string
		value string
		want  string
	}{
		{name: "duplicate", value: `{"name":"alice","name":"bob"}`, want: "duplicate"},
		{name: "unknown", value: `{"name":"alice","future":true}`, want: "unknown field"},
		{name: "trailing", value: `{"name":"alice"} {}`, want: "trailing"},
		{name: "empty", value: ``, want: "EOF"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var got payload
			err := Decode([]byte(test.value), &got, true)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Decode() error = %v, want %q", err, test.want)
			}
		})
	}
}

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
