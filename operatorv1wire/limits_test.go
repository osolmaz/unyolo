package operatorv1wire

import (
	"testing"

	"github.com/oapi-codegen/nullable"
	"github.com/osolmaz/brokerkit/usebudget"
)

func TestUseLimitWireRoundTrip(t *testing.T) {
	t.Parallel()
	for _, limit := range []usebudget.Limit{usebudget.Unlimited, 3} {
		if got := UseLimitFromWire(UseLimitToWire(limit)); got != limit {
			t.Fatalf("round trip %v = %v", limit, got)
		}
	}
	if got := UseLimitFromWire(nullable.Nullable[int]{}); !got.IsUnlimited() {
		t.Fatalf("unspecified = %v", got)
	}
}
