package operatorapi_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operatorinbox"
)

func TestContractFixturesRoundTripAndContainNoAuthority(t *testing.T) {
	listData, err := os.ReadFile("testdata/list.json")
	if err != nil {
		t.Fatal(err)
	}
	var page operatorinbox.Page
	if err := json.Unmarshal(listData, &page); err != nil || len(page.Items) != 1 {
		t.Fatalf("list fixture = %+v, %v", page, err)
	}
	eventData, err := os.ReadFile("testdata/event.json")
	if err != nil {
		t.Fatal(err)
	}
	var event grants.Event
	if err := json.Unmarshal(eventData, &event); err != nil || event.Kind != grants.EventRequestCreated {
		t.Fatalf("event fixture = %+v, %v", event, err)
	}
	combined := strings.ToLower(string(append(listData, eventData...)))
	for _, forbidden := range []string{"decision_token", "authorization", "credential", "private_key"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("fixtures contain protected field %q", forbidden)
		}
	}
}
