package opbinding

import (
	"encoding/json"
	"testing"
)

func TestPinnedBindingsLoadAndValidateClosedSchemas(t *testing.T) {
	bindings, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 103 {
		t.Fatalf("binding count = %d, want 103", len(bindings))
	}
	binding, found := ByName("webhook.enable")
	if !found || binding.Method != "POST" || binding.FixedPath["action"] != "enable" {
		t.Fatalf("webhook.enable = %+v, %v", binding, found)
	}
	if err := binding.Validate(json.RawMessage(`{"webhookId":"0123456789abcdef01234567"}`), json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := binding.Validate(json.RawMessage(`{"webhookId":"0123456789abcdef01234567","action":"disable"}`), json.RawMessage(`{}`)); err == nil {
		t.Fatal("fixed action was accepted from the requester")
	}
}

func TestBindingValidationRejectsDuplicateAndUnknownFields(t *testing.T) {
	binding, found := ByName("bucket.create")
	if !found {
		t.Fatal("bucket.create binding is missing")
	}
	validTarget := json.RawMessage(`{"namespace":"alice","repo":"artifacts"}`)
	if err := binding.Validate(validTarget, json.RawMessage(`{"private":true}`)); err != nil {
		t.Fatal(err)
	}
	for _, target := range []json.RawMessage{
		json.RawMessage(`{"namespace":"alice","namespace":"bob","repo":"artifacts"}`),
		json.RawMessage(`{"namespace":"alice","repo":"artifacts","url":"https://example.com"}`),
	} {
		if err := binding.Validate(target, json.RawMessage(`{"private":true}`)); err == nil {
			t.Fatalf("invalid target accepted: %s", target)
		}
	}
}
