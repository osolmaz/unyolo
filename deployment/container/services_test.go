package container

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func brokerFixture(name string) BrokerService {
	return BrokerService{
		Name:           name,
		Image:          "ghcr.io/osolmaz/" + name + ":1.0" + validDigest,
		User:           "10001:10001",
		StateVolume:    "unyolo-" + name + "-state",
		StateTarget:    "/var/lib/" + name,
		ConfigVolume:   "unyolo-" + name + "-config",
		ConfigTarget:   "/etc/" + name,
		Secrets:        []BrokerSecret{{Name: name + "-agent-secret", File: "secrets/" + name + "-agent-secret"}},
		ListenerPort:   8443,
		HealthArgs:     []string{"CMD", "/opt/unyolo/health"},
		HealthInterval: "10s",
	}
}

func TestBuildServicesProjectDeterministic(t *testing.T) {
	options := ServicesOptions{
		ProjectName:      "unyolo-services",
		NetworkName:      "unyolo-net",
		InstallationName: "default",
		Brokers:          []BrokerService{brokerFixture("gh-broker"), brokerFixture("hf-broker")},
	}
	first, err := BuildServicesProject(options)
	if err != nil {
		t.Fatalf("BuildServicesProject: %v", err)
	}
	firstYAML, err := first.Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	second, err := BuildServicesProject(options)
	if err != nil {
		t.Fatalf("BuildServicesProject: %v", err)
	}
	secondYAML, err := second.Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !bytes.Equal(firstYAML, secondYAML) {
		t.Fatalf("services render is not deterministic")
	}
	got := string(firstYAML)
	for _, want := range []string{
		"name: unyolo-services",
		"gh-broker:",
		"hf-broker:",
		"cap_drop:",
		"read_only: true",
		"no-new-privileges:true",
		"unyolo-gh-broker-state:",
		"unyolo-gh-broker-config:",
		"gh-broker-agent-secret:",
		"file: secrets/gh-broker-agent-secret",
		"networks:\n  unyolo-net",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("services YAML missing %q\n%s", want, got)
		}
	}
	if strings.Contains(got, "docker.sock") {
		t.Fatalf("services YAML must not reference docker.sock:\n%s", got)
	}
}

func TestBuildServicesRejectsSharedSecrets(t *testing.T) {
	shared := brokerFixture("hf-broker")
	shared.Secrets = []BrokerSecret{{Name: "gh-broker-agent-secret", File: "secrets/gh-broker-agent-secret"}}
	options := ServicesOptions{
		ProjectName:      "unyolo-services",
		NetworkName:      "unyolo-net",
		InstallationName: "default",
		Brokers:          []BrokerService{brokerFixture("gh-broker"), shared},
	}
	if _, err := BuildServicesProject(options); err == nil {
		t.Fatal("expected shared secret to be rejected")
	}
}

func TestBuildServicesRejectsUnpinnedImage(t *testing.T) {
	broker := brokerFixture("gh-broker")
	broker.Image = "ghcr.io/osolmaz/gh-broker:1.0"
	options := ServicesOptions{
		ProjectName:      "unyolo-services",
		NetworkName:      "unyolo-net",
		InstallationName: "default",
		Brokers:          []BrokerService{broker},
	}
	if _, err := BuildServicesProject(options); err == nil {
		t.Fatal("expected unpinned image to be rejected")
	}
}

func TestBuildServicesRejectsSharedVolumes(t *testing.T) {
	other := brokerFixture("hf-broker")
	other.StateVolume = "unyolo-gh-broker-state"
	options := ServicesOptions{
		ProjectName:      "unyolo-services",
		NetworkName:      "unyolo-net",
		InstallationName: "default",
		Brokers:          []BrokerService{brokerFixture("gh-broker"), other},
	}
	if _, err := BuildServicesProject(options); err == nil {
		t.Fatal("expected shared state volume to be rejected")
	}
}

func TestServicesLifecycleWritesFilesAndRolls(t *testing.T) {
	directory := t.TempDir()
	project, err := BuildServicesProject(ServicesOptions{
		ProjectName:      "unyolo-services",
		NetworkName:      "unyolo-net",
		InstallationName: "default",
		Brokers:          []BrokerService{brokerFixture("gh-broker")},
	})
	if err != nil {
		t.Fatalf("BuildServicesProject: %v", err)
	}
	result, rollback, err := PlanServices(ServicesPlanInputs{Directory: directory, Project: project})
	if err != nil {
		t.Fatalf("PlanServices: %v", err)
	}
	receiptPath, err := WriteReceipt(directory, project, "default")
	if err != nil {
		t.Fatalf("WriteReceipt: %v", err)
	}
	receipt, err := LoadReceipt(receiptPath)
	if err != nil {
		t.Fatalf("LoadReceipt: %v", err)
	}
	if receipt.ProjectName != "unyolo-services" || len(receipt.Volumes) == 0 {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
	if err := rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if _, existed, err := readExisting(result.ComposePath); err != nil || existed {
		t.Fatalf("compose should be gone after rollback: existed=%v err=%v", existed, err)
	}
}

func TestDestroyVolumesRequiresConfirmation(t *testing.T) {
	if err := DestroyVolumes(context.Background(), &fakeRunner{}, ServicesReceipt{APIVersion: receiptAPIVersion, Volumes: []string{"unyolo-gh-broker-state"}}, false); err == nil {
		t.Fatal("expected unconfirmed destruction to fail")
	}
	if err := DestroyVolumes(context.Background(), &fakeRunner{}, ServicesReceipt{APIVersion: "bogus", Volumes: []string{"unyolo-gh-broker-state"}}, true); err == nil {
		t.Fatal("expected invalid receipt to fail")
	}
	runner := &fakeRunner{}
	if err := DestroyVolumes(context.Background(), runner, ServicesReceipt{APIVersion: receiptAPIVersion, Volumes: []string{"unyolo-gh-broker-state"}}, true); err != nil {
		t.Fatalf("DestroyVolumes: %v", err)
	}
	if len(runner.args) < 3 || runner.args[0] != "volume" || runner.args[1] != "rm" {
		t.Fatalf("expected volume rm invocation, got %v", runner.args)
	}
}
