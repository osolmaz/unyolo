package providercredential

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeEvaluateAndBind(t *testing.T) {
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	snapshot, err := Normalize(Snapshot{
		Provider: "test", CredentialKind: "fine-grained", Subject: "alice",
		FingerprintSHA256: strings.Repeat("a", 64), Generation: 7, VerifiedAt: now,
		VerificationState: VerificationValid,
		Capabilities: []Capability{
			{Domain: "repo", Permission: "contents", AccessLevel: AccessRead, Resource: ResourceSelector{Kind: "repo", Name: "alice/private"}},
			{Domain: "repo", Permission: "contents", AccessLevel: AccessRead, Resource: ResourceSelector{Kind: "repo", Name: "alice/private"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Capabilities) != 1 || len(snapshot.CapabilityDigest) != 64 {
		t.Fatalf("snapshot was not normalized: %+v", snapshot)
	}
	requirement := Requirement{AllOf: []AnyOf{{Alternatives: []Need{{Domain: "repo", Permission: "contents", MinimumAccessLevel: AccessRead, TargetBinding: "repo"}}}}}
	if result := Evaluate(snapshot, requirement, Target{"repo": "alice/private"}); !result.Allowed {
		t.Fatalf("expected covered target: %+v", result)
	}
	if result := Evaluate(snapshot, requirement, Target{"repo": "alice/other"}); result.Allowed || len(result.Missing) != 1 {
		t.Fatalf("expected bounded refusal: %+v", result)
	}
	if err := ValidateBinding(snapshot, Bind(snapshot)); err != nil {
		t.Fatal(err)
	}
	changed := snapshot
	changed.Generation++
	if err := ValidateBinding(changed, Bind(snapshot)); err == nil {
		t.Fatal("stale generation was accepted")
	}
}

func TestServiceRequiresMonotonicGeneration(t *testing.T) {
	snapshot := Snapshot{Provider: "test", CredentialKind: "app", Subject: "app",
		FingerprintSHA256: strings.Repeat("b", 64), Generation: 1, VerifiedAt: time.Now(), VerificationState: VerificationValid}
	service, err := NewService(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Replace(snapshot); err == nil {
		t.Fatal("same generation was accepted")
	}
	snapshot.Generation = 2
	if err := service.Replace(snapshot); err != nil {
		t.Fatal(err)
	}
}

func TestEvaluationUsesExactTargetsAndCallerTime(t *testing.T) {
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	expires := now.Add(time.Minute)
	snapshot, err := Normalize(Snapshot{
		Provider: "test", CredentialKind: "app", Subject: "app", FingerprintSHA256: strings.Repeat("c", 64),
		Generation: 1, VerifiedAt: now, ExpiresAt: &expires, VerificationState: VerificationValid,
		Capabilities: []Capability{{Domain: "repo", Permission: "contents", AccessLevel: AccessRead, Resource: ResourceSelector{Kind: "repo", Name: "acme/private"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	requirement := Requirement{AllOf: []AnyOf{{Alternatives: []Need{{Domain: "repo", Permission: "contents", MinimumAccessLevel: AccessRead, TargetBinding: "resource"}}}}}
	if !CanSatisfy(snapshot, requirement, now) || !EvaluateAt(snapshot, requirement, Target{"resource": "acme/private"}, now).Allowed {
		t.Fatal("scoped capability should be discoverable and match its exact target")
	}
	if EvaluateAt(snapshot, requirement, Target{"resource": "acme/other"}, now).Allowed {
		t.Fatal("scoped capability matched another target")
	}
	if EvaluateAt(snapshot, requirement, Target{"resource": "acme/private"}, expires).Allowed {
		t.Fatal("expired credential was accepted")
	}
}

func TestSecretClears(t *testing.T) {
	secret, err := NewSecret([]byte("candidate"))
	if err != nil {
		t.Fatal(err)
	}
	secret.Clear()
	if _, err := secret.Bytes(); err == nil {
		t.Fatal("cleared secret remained readable")
	}
}

func TestTargetFromJSON(t *testing.T) {
	target, err := TargetFromJSON([]byte(`{"owner":"acme","name":"repo","count":2,"empty":""}`))
	if err != nil || target["resource"] != "acme/repo" || target["count"] != "" {
		t.Fatalf("target = %#v, %v", target, err)
	}
	target, err = TargetFromJSON([]byte(`{"namespace":"team","repo":"project"}`))
	if err != nil || target["resource"] != "team/project" {
		t.Fatalf("namespace target = %#v, %v", target, err)
	}
	for _, invalid := range [][]byte{nil, []byte(`[]`), []byte(`{"owner":"a"} {}`), make([]byte, 64*1024+1)} {
		if _, err := TargetFromJSON(invalid); err == nil {
			t.Fatalf("TargetFromJSON(%q) succeeded", invalid)
		}
	}
}

func TestSnapshotValidationRejectsMalformedAuthority(t *testing.T) {
	base := Snapshot{Provider: "test", CredentialKind: "app", Subject: "subject", FingerprintSHA256: strings.Repeat("a", 64),
		Generation: 1, VerifiedAt: time.Now().UTC(), VerificationState: VerificationValid}
	tests := []func(*Snapshot){
		func(value *Snapshot) { value.SchemaVersion = 2 },
		func(value *Snapshot) { value.Generation = 0 },
		func(value *Snapshot) { value.Provider = "bad name" },
		func(value *Snapshot) { value.Subject = " " },
		func(value *Snapshot) { value.FingerprintSHA256 = "bad" },
		func(value *Snapshot) { value.VerifiedAt = time.Time{} },
		func(value *Snapshot) { value.VerificationState = "unknown" },
		func(value *Snapshot) { expired := value.VerifiedAt; value.ExpiresAt = &expired },
		func(value *Snapshot) {
			value.Capabilities = []Capability{{Domain: "bad name", Permission: "read", AccessLevel: AccessRead}}
		},
		func(value *Snapshot) {
			value.Capabilities = []Capability{{Domain: "repo", Permission: "read", AccessLevel: "owner"}}
		},
		func(value *Snapshot) {
			value.Capabilities = []Capability{{Domain: "repo", Permission: "read", AccessLevel: AccessRead, Resource: ResourceSelector{Name: " bad"}}}
		},
	}
	for index, mutate := range tests {
		value := base
		mutate(&value)
		if _, err := Normalize(value); err == nil {
			t.Fatalf("invalid snapshot %d succeeded", index)
		}
	}
}

func TestServiceOperationsAndUnavailableState(t *testing.T) {
	var unavailable *Service
	if _, err := unavailable.Snapshot(); err == nil || unavailable.Evaluate(Requirement{}, nil).Allowed || unavailable.CanSatisfy(Requirement{}, time.Now()) {
		t.Fatal("unavailable service did not fail closed")
	}
	if _, err := unavailable.Binding(); err == nil || unavailable.Validate(Binding{}) == nil {
		t.Fatal("unavailable service returned a binding")
	}
	snapshot := Snapshot{Provider: "test", CredentialKind: "app", Subject: "subject", FingerprintSHA256: strings.Repeat("e", 64),
		Generation: 1, VerifiedAt: time.Now().UTC(), VerificationState: VerificationValid,
		Capabilities: []Capability{{Domain: "repo", Permission: "contents", AccessLevel: AccessWrite}}}
	service, err := NewService(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	requirement := Requirement{AllOf: []AnyOf{{Alternatives: []Need{{Domain: "repo", Permission: "contents", MinimumAccessLevel: AccessRead}}}}}
	if !service.Evaluate(requirement, nil).Allowed || !service.CanSatisfy(requirement, time.Now()) {
		t.Fatal("service did not evaluate its snapshot")
	}
	binding, err := service.Binding()
	if err != nil || service.Validate(binding) != nil {
		t.Fatalf("binding = %+v, %v", binding, err)
	}
	copy, _ := service.Snapshot()
	copy.Capabilities[0].Permission = "changed"
	stable, _ := service.Snapshot()
	if stable.Capabilities[0].Permission != "contents" {
		t.Fatal("snapshot returned mutable capability storage")
	}
	invalid := snapshot
	invalid.Generation = 2
	invalid.Provider = "bad name"
	if service.Replace(invalid) == nil {
		t.Fatal("service accepted invalid replacement")
	}
}

func TestSecretBoundsAndNilClear(t *testing.T) {
	if _, err := NewSecret(nil); err == nil {
		t.Fatal("empty secret accepted")
	}
	if _, err := NewSecret(make([]byte, maxSecretBytes+1)); err == nil {
		t.Fatal("oversized secret accepted")
	}
	var secret *Secret
	secret.Clear()
	if _, err := secret.Bytes(); err == nil {
		t.Fatal("nil secret readable")
	}
}
