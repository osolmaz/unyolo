package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/credential/store"
	"github.com/osolmaz/brokerkit/internal/storage/sealed"
)

type credentialOutputFake struct {
	identity string
	response json.RawMessage
	result   error
	request  json.RawMessage
}

func (f *credentialOutputFake) WhoAmI(context.Context) (hubclient.Identity, error) {
	return hubclient.Identity{Name: f.identity}, nil
}

func (f *credentialOutputFake) ExecuteBound(context.Context, string, json.RawMessage, json.RawMessage) error {
	return errors.New("unexpected generic execution")
}

func (f *credentialOutputFake) ExecuteBoundResult(_ context.Context, _ string, _ json.RawMessage, arguments json.RawMessage) (json.RawMessage, error) {
	f.request = bytes.Clone(arguments)
	return bytes.Clone(f.response), f.result
}

func (f *credentialOutputFake) ObserveBound(context.Context, string, json.RawMessage) (json.RawMessage, bool, error) {
	return nil, false, nil
}

type credentialSlotFake struct {
	slot, kind string
	secret     []byte
	err        error
}

func (f *credentialSlotFake) Put(slot, kind string, secret []byte) (credentialstore.Metadata, error) {
	f.slot, f.kind, f.secret = slot, kind, bytes.Clone(secret)
	return credentialstore.Metadata{Slot: slot, Kind: kind, Digest: "redacted", Size: len(secret)}, f.err
}

func TestCredentialOutputAdapterStoresTokenWithoutReturningIt(t *testing.T) {
	payloads, _ := sealedstore.Open(t.TempDir())
	client := &credentialOutputFake{identity: "operator", response: json.RawMessage(`{"token":"hf_generated-secret","tokenInfo":{"_id":"token-1","displayName":"deploy","createdAt":"2026-07-13T00:00:00Z"}}`)}
	slots := &credentialSlotFake{}
	adapters, err := NewCredentialOutputAdapters(client, payloads, slots)
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := NewRegistry(adapters...)
	adapter, found := registry.Lookup("service_account.token.create")
	if !found {
		t.Fatal("token adapter missing")
	}
	target := json.RawMessage(`{"name":"acme","serviceAccountId":"0123456789abcdef01234567"}`)
	arguments := json.RawMessage(`{"public":{"permissions":["repo.content.read"]},"credential_slot":"deployment-token"}`)
	input, err := adapter.Decode(target, arguments)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Resolve(t.Context(), input)
	if err != nil || plan.Policy.Attrs["credential_slot"] != "deployment-token" || !bytes.Contains([]byte(plan.Presentation.Summary), []byte("deployment-token")) {
		t.Fatalf("plan=%#v err=%v", plan, err)
	}
	assertPlanReconstruction(t, adapter, plan)
	plan.Policy = adapter.Authorize(plan)
	if plan.Policy.Attrs["credential_kind"] != "hf-service-account-token" {
		t.Fatalf("reconstructed policy = %#v", plan.Policy)
	}
	if err := hfpolicy.ValidateRequest(plan.Policy); err != nil {
		t.Fatalf("Authorize() produced an invalid policy request: %v", err)
	}
	outcome, err := adapter.Execute(t.Context(), plan)
	if err != nil || !outcome.Proven || slots.slot != "deployment-token" || string(slots.secret) != "hf_generated-secret" {
		t.Fatalf("outcome=%#v slot=%#v err=%v", outcome, slots, err)
	}
	if bytes.Contains(outcome.Result, []byte("hf_generated-secret")) || bytes.Contains(client.request, []byte("credential_slot")) {
		t.Fatalf("secret or broker metadata leaked: result=%s request=%s", outcome.Result, client.request)
	}
	var publicResult map[string]any
	if json.Unmarshal(outcome.Result, &publicResult) != nil || len(publicResult) != 3 || publicResult["stored"] != true ||
		publicResult["slot"] != "deployment-token" || publicResult["kind"] != "hf-service-account-token" {
		t.Fatalf("credential result exposed unexpected fields: %s", outcome.Result)
	}
	if reconciled, err := adapter.Reconcile(t.Context(), plan); err != nil || reconciled.Proven {
		t.Fatalf("credential output reconciled = %#v, %v", reconciled, err)
	}
}

func TestCredentialOutputAdapterFailsClosed(t *testing.T) {
	payloads, _ := sealedstore.Open(t.TempDir())
	client := &credentialOutputFake{identity: "operator", response: json.RawMessage(`{"token":"hf_secret","tokenInfo":{"_id":"token-1","displayName":"deploy","createdAt":"now"}}`)}
	slots := &credentialSlotFake{err: errors.New("disk full")}
	adapters, _ := NewCredentialOutputAdapters(client, payloads, slots)
	registry, _ := NewRegistry(adapters...)
	adapter, _ := registry.Lookup("service_account.token.create")
	target := json.RawMessage(`{"name":"acme","serviceAccountId":"0123456789abcdef01234567"}`)
	if _, err := adapter.Decode(target, json.RawMessage(`{"public":{},"credential_slot":"../escape"}`)); err == nil {
		t.Fatal("invalid output slot accepted")
	}
	input, _ := adapter.Decode(target, json.RawMessage(`{"public":{"permissions":["repo.content.read"]},"credential_slot":"deployment-token"}`))
	plan, err := adapter.Resolve(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Execute(t.Context(), plan); err == nil || err.Error() != "upstream_result_unknown" {
		t.Fatalf("slot failure = %v", err)
	}
	client.response = json.RawMessage(`{"token":"missing-token-info"}`)
	slots.err = nil
	if _, err := adapter.Execute(t.Context(), plan); err == nil || err.Error() != "upstream_result_unknown" {
		t.Fatalf("malformed success = %v", err)
	}
}

func TestDeepLinkOutputIsStoredAsCredential(t *testing.T) {
	payloads, _ := sealedstore.Open(t.TempDir())
	client := &credentialOutputFake{identity: "operator", response: json.RawMessage(`{"purpose":"dashboard","url":"https://huggingface.co/deep-link/secret","expires_at":"2026-07-13T01:00:00Z"}`)}
	slots := &credentialSlotFake{}
	adapters, err := NewCredentialOutputAdapters(client, payloads, slots)
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := NewRegistry(adapters...)
	adapter, found := registry.Lookup("provisioning.deep_link.create")
	if !found {
		t.Fatal("deep-link credential adapter missing")
	}
	input, err := adapter.Decode(json.RawMessage(`{}`), json.RawMessage(`{"public":{"purpose":"dashboard"},"credential_slot":"dashboard-link"}`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Resolve(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := adapter.Execute(t.Context(), plan)
	if err != nil || !outcome.Proven || slots.kind != "hf-provisioning-deep-link" || !bytes.Contains(slots.secret, []byte("deep-link/secret")) {
		t.Fatalf("outcome=%s slot=%+v err=%v", outcome.Result, slots, err)
	}
	if bytes.Contains(outcome.Result, []byte("deep-link/secret")) {
		t.Fatalf("deep link leaked in operation result: %s", outcome.Result)
	}
}
