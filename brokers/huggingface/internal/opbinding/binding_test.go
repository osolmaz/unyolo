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
	if len(bindings) != 105 {
		t.Fatalf("binding count = %d, want 105", len(bindings))
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

func TestEndpointBindingsKeepSecretsInSealedModelField(t *testing.T) {
	create, found := ByName("endpoint.create")
	if !found || create.Origin != "inference_endpoints" || create.Method != "POST" {
		t.Fatalf("endpoint.create binding = %+v", create)
	}
	target := []byte(`{"namespace":"acme"}`)
	public := []byte(`{"compute":{"accelerator":"gpu","instanceSize":"x1","instanceType":"nvidia-a10g","scaling":{"maxReplica":1,"minReplica":0}},"model":{"framework":"pytorch","repository":"acme/model","image":{"huggingface":{}}},"name":"demo","provider":{"region":"us-east-1","vendor":"aws"},"type":"authenticated"}`)
	if err := create.Validate(target, public); err != nil {
		t.Fatal(err)
	}
	if err := create.Validate(target, []byte(`{"compute":{},"model":{"secrets":{"TOKEN":"secret"}},"name":"demo","provider":{},"type":"authenticated"}`)); err == nil {
		t.Fatal("invalid endpoint configuration accepted")
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
