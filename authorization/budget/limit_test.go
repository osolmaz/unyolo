package usebudget

import (
	"encoding/json"
	"testing"
)

func TestLimitJSONAndBudgetSemantics(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		input     string
		want      Limit
		unlimited bool
	}{
		{name: "finite", input: "3", want: 3},
		{name: "maximum finite", input: "1000000", want: MaxFiniteUses},
		{name: "unlimited", input: "null", want: Unlimited, unlimited: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var limit Limit
			if err := json.Unmarshal([]byte(test.input), &limit); err != nil {
				t.Fatal(err)
			}
			if limit != test.want || limit.IsUnlimited() != test.unlimited {
				t.Fatalf("limit = %v", limit)
			}
			encoded, err := json.Marshal(limit)
			if err != nil || string(encoded) != test.input {
				t.Fatalf("Marshal() = %s, %v", encoded, err)
			}
		})
	}
	for _, input := range []string{"0", "1000001"} {
		var limit Limit
		if err := json.Unmarshal([]byte(input), &limit); err == nil {
			t.Fatalf("Unmarshal(%s) succeeded", input)
		}
	}
	if !Unlimited.Allows(10_000, 20) || Unlimited.Exhausted(10_000) {
		t.Fatal("unlimited budget was exhausted")
	}
	if Limit(3).Allows(2, 1) || !Limit(3).Exhausted(3) {
		t.Fatal("finite budget ignored its ceiling")
	}
}

func TestOptionalDistinguishesOmittedNullAndFinite(t *testing.T) {
	t.Parallel()
	var envelope struct {
		MaxUses Optional `json:"max_uses"`
	}
	if err := json.Unmarshal([]byte(`{}`), &envelope); err != nil || envelope.MaxUses.Specified {
		t.Fatalf("omitted = %+v, %v", envelope.MaxUses, err)
	}
	if err := json.Unmarshal([]byte(`{"max_uses":null}`), &envelope); err != nil ||
		!envelope.MaxUses.Specified || !envelope.MaxUses.Limit.IsUnlimited() {
		t.Fatalf("null = %+v, %v", envelope.MaxUses, err)
	}
	if err := json.Unmarshal([]byte(`{"max_uses":4}`), &envelope); err != nil ||
		!envelope.MaxUses.Specified || envelope.MaxUses.Limit != 4 {
		t.Fatalf("finite = %+v, %v", envelope.MaxUses, err)
	}
}
