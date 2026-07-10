package validatex

import "testing"

func TestAccountNames(t *testing.T) {
	if err := AccountNames(map[string]string{"user": "broker_user-1.example"}); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", "1broker", "%u", "root\nGroup=root", "broker name"} {
		if err := AccountNames(map[string]string{"user": value}); err == nil {
			t.Fatalf("AccountNames(%q) error = nil", value)
		}
	}
}
