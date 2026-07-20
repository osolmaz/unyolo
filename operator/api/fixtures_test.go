package operatorapi_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/operator/v1"
)

func TestContractFixturesRoundTripAndContainNoAuthority(t *testing.T) {
	listData, err := os.ReadFile("testdata/list.json")
	if err != nil {
		t.Fatal(err)
	}
	var page operatorv1.Page
	if err := json.Unmarshal(listData, &page); err != nil || len(page.Requests) != 1 {
		t.Fatalf("list fixture = %+v, %v", page, err)
	}
	eventData, err := os.ReadFile("testdata/event.json")
	if err != nil {
		t.Fatal(err)
	}
	var event operatorv1.Event
	if err := json.Unmarshal(eventData, &event); err != nil || event.Kind != "request.created" {
		t.Fatalf("event fixture = %+v, %v", event, err)
	}
	combined := strings.ToLower(string(append(listData, eventData...)))
	for _, forbidden := range []string{"decision_token", "authorization", "credential", "private_key"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("fixtures contain protected field %q", forbidden)
		}
	}
}
