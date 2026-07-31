package capability

import (
	"testing"

	"github.com/osolmaz/unyolo/internal/host/bundle"
)

type probe map[Feature]bool

func (value probe) Available(feature Feature, _ string) bool { return value[feature] }

func TestResolveIntersectsSignedAndLiveCapabilities(t *testing.T) {
	t.Parallel()
	manifest := bundle.Manifest{
		OperatingSystem: "linux", Architecture: "arm64",
		SetupCapabilities: bundle.SetupCapabilities{
			NativeServiceBackend: "systemd",
			Features:             []string{string(FeatureTLS), string(FeatureDockerAgent), string(FeatureLocalSocket)},
			Integrations:         []string{"openclaw"},
		},
	}
	value, err := Resolve(manifest, probe{FeatureTLS: true, FeatureDockerAgent: false, FeatureLocalSocket: true})
	if err != nil {
		t.Fatal(err)
	}
	if !value.Has(FeatureTLS) || !value.Has(FeatureLocalSocket) || value.Has(FeatureDockerAgent) {
		t.Fatalf("unexpected capability intersection: %#v", value.Features)
	}
	if err := value.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestResolveRejectsUnknownSignedCapability(t *testing.T) {
	t.Parallel()
	manifest := bundle.Manifest{OperatingSystem: "linux", Architecture: "arm64", SetupCapabilities: bundle.SetupCapabilities{Features: []string{"future"}}}
	if _, err := Resolve(manifest, probe{}); err == nil {
		t.Fatal("expected unknown capability rejection")
	}
}

func TestSnapshotDetectsChangedCapability(t *testing.T) {
	t.Parallel()
	manifest := bundle.Manifest{OperatingSystem: "linux", Architecture: "arm64", SetupCapabilities: bundle.SetupCapabilities{Features: []string{string(FeatureTLS)}}}
	value, err := Resolve(manifest, probe{FeatureTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	value.Features = nil
	if err := value.Validate(); err == nil {
		t.Fatal("expected digest rejection")
	}
}
