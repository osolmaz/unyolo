package opbinding

import (
	"encoding/json"
	"net/http"
	"slices"
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

func TestNotificationBindingsExposeOpenAPIQueryParameters(t *testing.T) {
	binding, found := ByName("notification.delete")
	if !found {
		t.Fatal("notification.delete binding missing")
	}
	want := []string{"applyToAll", "articleId", "lastUpdate", "mention", "p", "paperId", "postAuthor", "readStatus", "repoName", "repoType"}
	if !slices.Equal(binding.QueryParameters, want) {
		t.Fatalf("query parameters = %v, want %v", binding.QueryParameters, want)
	}
	target := json.RawMessage(`{"repoType":"dataset","repoName":"acme/demo","readStatus":"unread","applyToAll":true}`)
	if err := binding.Validate(target, json.RawMessage(`{"discussionIds":["0123456789abcdef01234567"]}`)); err != nil {
		t.Fatal(err)
	}
}

func TestCapturedResultUsesPinnedSuccessSchema(t *testing.T) {
	binding, found := ByName("collection.create")
	if !found || !binding.CaptureResult || len(binding.ResultSchema) == 0 {
		t.Fatalf("collection.create result binding = %+v, %v", binding, found)
	}
	valid := json.RawMessage(`{"slug":"demo","title":"Demo","lastUpdated":"2026-07-13T00:00:00Z","gating":false,"owner":{"_id":"0123456789abcdef01234567","avatarUrl":"","fullname":"Alice","name":"alice","isHf":false,"isHfAdmin":false,"isMod":false,"type":"user","isPro":false},"position":0,"theme":"orange","private":false,"upvotes":0,"shareUrl":"https://huggingface.co/collections/alice/demo","isUpvotedByUser":false,"items":[]}`)
	if err := binding.ValidateResult(valid); err != nil {
		t.Fatal(err)
	}
	if err := binding.ValidateResult(json.RawMessage(`{"slug":"demo","unexpected":true}`)); err == nil {
		t.Fatal("invalid captured result was accepted")
	}
}

func TestBindingConstructionRejectsUnpinnedAndInvalidRoutes(t *testing.T) {
	closed := map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}
	for _, source := range []routeSource{
		{},
		{Operation: "test", Method: "TRACE", Path: "/api/test"},
		{Operation: "test", Method: http.MethodPost, Path: "relative"},
		{Operation: "test", Method: http.MethodPost, Path: "/api/test", TargetSchema: closed, ArgumentsSchema: closed},
		{Operation: "test", Method: http.MethodPost, Path: "/api/test", TargetSchema: closed, ArgumentsSchema: closed, UpstreamReference: "pinned", ObserveMethod: "TRACE", ObservePath: "/api/test", Reconcile: "present"},
		{Operation: "test", Method: http.MethodPost, Path: "/api/test", TargetSchema: closed, ArgumentsSchema: closed, UpstreamReference: "pinned", Transform: "shell"},
	} {
		if _, err := bindingFromSource(nil, nil, source); err == nil {
			t.Fatalf("invalid route accepted: %+v", source)
		}
	}
	if _, err := bindingFromSource(map[string]map[string]json.RawMessage{}, nil, routeSource{Operation: "test", Method: http.MethodPost, Path: "/missing"}); err == nil {
		t.Fatal("missing OpenAPI path accepted")
	}
	paths := map[string]map[string]json.RawMessage{"/api/test": {"get": json.RawMessage(`{}`)}}
	if _, err := bindingFromSource(paths, nil, routeSource{Operation: "test", Method: http.MethodPost, Path: "/api/test"}); err == nil {
		t.Fatal("missing OpenAPI method accepted")
	}
}

func TestSchemaProjectionCoversFixedAndNonObjectBodies(t *testing.T) {
	parameters := []parameter{
		{Name: "namespace", In: "path", Required: true, Schema: map[string]any{"type": "string"}},
		{Name: "fixed", In: "path", Required: true, Schema: map[string]any{"type": "string"}},
		{Name: "query", In: "query", Schema: map[string]any{"type": "string"}},
	}
	schema := schemaForParameters(parameters, "path", map[string]any{"fixed": "value"})
	if len(schema["required"].([]string)) != 1 {
		t.Fatalf("parameter schema = %#v", schema)
	}
	operation := operationDocument{RequestBody: &requestBody{Content: map[string]mediaType{"application/json": {Schema: map[string]any{"type": "array", "items": map[string]any{"type": "string"}}}}}}
	if _, err := schemaForArguments(operation, nil, ""); err == nil {
		t.Fatal("non-object body without projection accepted")
	}
	projected, err := schemaForArguments(operation, nil, "items")
	if err != nil || projected["type"] != "object" {
		t.Fatalf("projected schema = %#v, %v", projected, err)
	}
	nonJSON := operationDocument{RequestBody: &requestBody{Content: map[string]mediaType{"text/plain": {}}}}
	if _, err := schemaForArguments(nonJSON, nil, ""); err == nil {
		t.Fatal("non-JSON body accepted")
	}
	if _, err := compileECMAScriptRegexp("["); err == nil {
		t.Fatal("invalid ECMAScript regexp accepted")
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

func TestPublicArgumentsValidatorOmitsSealedPaths(t *testing.T) {
	binding, found := ByName("space.secret.set")
	if !found {
		t.Fatal("space.secret.set binding is missing")
	}
	validator, err := binding.PublicArgumentsValidator([]string{"value"})
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(json.RawMessage(`{"key":"TOKEN"}`)); err != nil {
		t.Fatalf("public arguments rejected: %v", err)
	}
	if err := validator.Validate(json.RawMessage(`{"key":"TOKEN","value":"leak"}`)); err == nil {
		t.Fatal("sealed field was accepted in public arguments")
	}
	if _, err := binding.PublicArgumentsValidator([]string{"missing.secret"}); err == nil {
		t.Fatal("missing sealed schema path was accepted")
	}
	endpoint, found := ByName("endpoint.update")
	if !found {
		t.Fatal("endpoint.update binding is missing")
	}
	endpointValidator, err := endpoint.PublicArgumentsValidator([]string{"model.secrets"})
	if err != nil {
		t.Fatal(err)
	}
	if err := endpointValidator.Validate(json.RawMessage(`{"model":{}}`)); err != nil {
		t.Fatalf("secrets-only endpoint update was rejected: %v", err)
	}
}

func TestRemoveSchemaPathFollowsReferencesAndCompositions(t *testing.T) {
	schema := map[string]any{
		"$ref": "#/$defs/root",
		"$defs": map[string]any{"root": map[string]any{
			"oneOf": []any{
				map[string]any{"type": "object", "properties": map[string]any{"public": map[string]any{"type": "string"}}},
				map[string]any{"type": "object", "properties": map[string]any{"secret": map[string]any{"type": "string"}}, "required": []any{"secret"}},
			},
		}},
	}
	found, err := removeSchemaPath(schema, schema, []string{"secret"})
	if err != nil || !found {
		t.Fatalf("removeSchemaPath() = %v, %v", found, err)
	}
	root := schema["$defs"].(map[string]any)["root"].(map[string]any)
	branch := root["oneOf"].([]any)[1].(map[string]any)
	if branch["properties"].(map[string]any)["secret"] != nil || branch["required"] != nil {
		t.Fatalf("sealed path remained in schema: %#v", branch)
	}
}

func TestDecrementMinimumProperties(t *testing.T) {
	schema := map[string]any{"minProperties": float64(2)}
	decrementMinimumProperties(schema)
	if schema["minProperties"] != float64(1) {
		t.Fatalf("minProperties = %#v", schema["minProperties"])
	}
	decrementMinimumProperties(schema)
	if schema["minProperties"] != nil {
		t.Fatalf("minimum was not removed: %#v", schema)
	}
	decrementMinimumProperties(schema)
}

func TestPinnedBindingsCloseNestedObjects(t *testing.T) {
	binding, found := ByName("bucket.create")
	if !found {
		t.Fatal("bucket.create binding is missing")
	}
	target := json.RawMessage(`{"namespace":"alice","repo":"artifacts"}`)
	if err := binding.Validate(target, json.RawMessage(`{"cdn":[{"provider":"aws","region":"us","unexpected":true}]}`)); err == nil {
		t.Fatal("unknown nested field was accepted")
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
