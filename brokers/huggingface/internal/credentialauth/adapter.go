package credentialauth

import (
	"context"
	"errors"
	"strings"

	"github.com/osolmaz/brokerkit/credential/provider"
)

// Adapter projects Hugging Face fine-grained tokens into BrokerKit's shared model.
type Adapter struct {
	Inspector  Inspector
	Generation uint64
}

func (Adapter) Provider() string { return "huggingface" }

func (Adapter) Enrollment(context.Context) (providercredential.Enrollment, error) {
	return providercredential.Enrollment{
		URL:          TokenFormURL,
		Instructions: "Create a dedicated fine-grained token and choose the permissions and resources this broker may use.",
	}, nil
}

func (a Adapter) Inspect(ctx context.Context, secret *providercredential.Secret) (providercredential.Snapshot, error) {
	value, err := secret.Bytes()
	if err != nil {
		return providercredential.Snapshot{}, err
	}
	defer clear(value)
	inspection, err := a.Inspector.Inspect(ctx, string(value))
	if err != nil {
		return providercredential.Snapshot{}, err
	}
	generation := a.Generation
	if generation == 0 {
		generation = 1
	}
	return Snapshot(inspection, generation)
}

func (Adapter) Requirement(operation string) (providercredential.Requirement, bool) {
	return operationRequirement(operation)
}

func (Adapter) Probe(_ context.Context, snapshot providercredential.Snapshot) (providercredential.ProbeResult, error) {
	if snapshot.VerificationState != providercredential.VerificationValid {
		return providercredential.ProbeResult{State: providercredential.ProbeInvalid}, errors.New("Hugging Face credential is not valid") //nolint:staticcheck // Hugging Face is a proper name.
	}
	return providercredential.ProbeResult{State: providercredential.ProbeValid}, nil
}

// Snapshot converts provider inspection output into the shared immutable model.
func Snapshot(inspection Inspection, generation uint64) (providercredential.Snapshot, error) {
	capabilities := make([]providercredential.Capability, 0, len(inspection.GlobalPermissions)+len(inspection.Scopes))
	for _, permission := range inspection.GlobalPermissions {
		capabilities = append(capabilities, providerCapability("global", "", permission))
	}
	for _, scope := range inspection.Scopes {
		for _, permission := range scope.Permissions {
			capabilities = append(capabilities, providerCapability(scope.EntityType, scope.EntityName, permission))
		}
	}
	verified, err := inspection.VerifiedTime()
	if err != nil {
		return providercredential.Snapshot{}, err
	}
	return providercredential.Normalize(providercredential.Snapshot{
		Provider: "huggingface", CredentialKind: "fine_grained_user_token", Subject: inspection.Account,
		FingerprintSHA256: inspection.FingerprintSHA256, Generation: generation, VerifiedAt: verified,
		VerificationState: providercredential.VerificationValid, Capabilities: capabilities,
	})
}

func providerCapability(domain, resource, permission string) providercredential.Capability {
	return providercredential.Capability{
		Domain: domain, Permission: permission, AccessLevel: permissionAccess(permission),
		Resource: providercredential.ResourceSelector{Kind: domain, Name: resource},
	}
}

func permissionAccess(permission string) providercredential.AccessLevel {
	switch {
	case strings.HasSuffix(permission, ".write"):
		return providercredential.AccessWrite
	case strings.HasSuffix(permission, ".read"):
		return providercredential.AccessRead
	default:
		return providercredential.AccessNone
	}
}
