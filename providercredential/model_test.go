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
