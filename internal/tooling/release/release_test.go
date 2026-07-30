package release

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/deployment/profile"
	"github.com/osolmaz/unyolo/internal/host/bundle"
	"github.com/osolmaz/unyolo/internal/strictjson"
)

func TestValidate(t *testing.T) {
	valid := Options{Directory: ".", Broker: "test-broker", Command: "./cmd/test", Version: "v0.1.0", Dist: "dist"}
	if err := validate(valid); err != nil {
		t.Fatal(err)
	}
	for _, broker := range []string{"../bad", "bad\nforged", "bad name", "."} {
		valid.Broker = broker
		if err := validate(valid); err == nil {
			t.Fatalf("validate() accepted broker %q", broker)
		}
	}
}

func TestCreateReleaseWorkDirResolvesSymlinkedTempRoot(t *testing.T) {
	realRoot := t.TempDir()
	linkRoot := filepath.Join(t.TempDir(), "temp")
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", linkRoot)

	work, err := createReleaseWorkDir()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(work) })
	if strings.HasPrefix(work, linkRoot+string(filepath.Separator)) {
		t.Fatalf("release work directory retained symlinked root: %s", work)
	}
	resolved, err := filepath.EvalSymlinks(work)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != work {
		t.Fatalf("release work directory = %q, resolved = %q", work, resolved)
	}
}

func TestValidateDeploymentKitOptions(t *testing.T) {
	base := Options{
		Directory: ".", Broker: "unyolo", Command: "./cmd/unyolo", Version: "v1.0.0", Dist: "dist",
		SourceCommit: strings.Repeat("a", 40), ExtraCommands: map[string]string{"provider": "./provider"},
		ExtraFiles: map[string]string{"providers/test.json": "provider.json"}, DeploymentComponents: []string{"release.json"},
	}
	tests := []struct {
		name string
		edit func(*Options)
	}{
		{"wrong broker", func(value *Options) { value.Broker = "other" }},
		{"source commit", func(value *Options) { value.SourceCommit = "bad" }},
		{"empty descriptor", func(value *Options) { value.DeploymentComponents = []string{""} }},
		{"duplicate command name", func(value *Options) { value.ExtraCommands = map[string]string{"unyolo": "./provider"} }},
		{"empty command", func(value *Options) { value.ExtraCommands = map[string]string{"provider": ""} }},
		{"unsafe extra file", func(value *Options) { value.ExtraFiles = map[string]string{"../provider.json": "provider.json"} }},
		{"empty extra source", func(value *Options) { value.ExtraFiles = map[string]string{"providers/test.json": ""} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := base
			test.edit(&value)
			if err := validate(value); err == nil {
				t.Fatal("invalid deployment kit release options were accepted")
			}
		})
	}
}

func TestRepositoryDeploymentReleaseInputsExist(t *testing.T) {
	repository := filepath.Clean(filepath.Join("..", "..", ".."))
	descriptors := []string{
		"brokers/github/deployment/release.json",
		"brokers/huggingface/deployment/release.json",
		"brokers/sudo/deployment/release.json",
		"brokers/sudo/deployment/release-exec.json",
	}
	for _, relative := range descriptors {
		descriptorPath := filepath.Join(repository, filepath.FromSlash(relative))
		data, err := os.ReadFile(descriptorPath)
		if err != nil {
			t.Fatalf("read %s: %v", relative, err)
		}
		var descriptor deploymentReleaseComponent
		if err := strictjson.Decode(data, &descriptor, true); err != nil {
			t.Fatalf("decode %s: %v", relative, err)
		}
		directory := filepath.Dir(descriptorPath)
		sources := make([]string, 0, len(descriptor.AdditionalProfileFiles)+1)
		if descriptor.Profile != "" {
			sources = append(sources, descriptor.Profile)
		}
		for _, file := range descriptor.AdditionalProfileFiles {
			sources = append(sources, file.Source)
		}
		for _, source := range sources {
			path := filepath.Join(directory, filepath.FromSlash(source))
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatalf("release input %s referenced by %s: %v", source, relative, err)
			}
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				t.Fatalf("release input %s referenced by %s is not a regular file", source, relative)
			}
		}
	}
}

func TestLoadDeploymentComponentsRejectsInvalidSets(t *testing.T) {
	directory := t.TempDir()
	options := Options{Directory: directory, DeploymentComponents: []string{"missing.json"}}
	if _, err := loadDeploymentComponents(options, map[string]string{}); err == nil {
		t.Fatal("missing deployment descriptor was accepted")
	}
	writeReleaseFile(t, directory, "malformed.json", "{\n")
	options.DeploymentComponents = []string{"malformed.json"}
	if _, err := loadDeploymentComponents(options, map[string]string{}); err == nil {
		t.Fatal("malformed deployment descriptor was accepted")
	}
	writeReleaseFile(t, directory, "companion.json", `{
  "api_version":"unyolo.io/deployment-release-component/v1",
  "provider":"test","name":"helper","binary":"helper","destination":"bin/helper",
  "role":"companion","services":[],"agent_contract":false,
  "state_format_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","required":false
}`)
	options.DeploymentComponents = []string{"companion.json"}
	if _, err := loadDeploymentComponents(options, map[string]string{"helper": "/tmp/helper"}); err == nil {
		t.Fatal("deployment set without a selectable provider was accepted")
	}
}

func TestSafePathsRejectsSourceRemoval(t *testing.T) {
	directory := t.TempDir()
	for _, dist := range []string{directory, filepath.Dir(directory)} {
		if _, _, err := safePaths(directory, dist); err == nil {
			t.Fatalf("safePaths(%q, %q) accepted destructive output", directory, dist)
		}
	}
	if _, _, err := safePaths(directory, filepath.Join(directory, "dist")); err != nil {
		t.Fatalf("safePaths() rejected nested output: %v", err)
	}
}

func TestHostTarget(t *testing.T) {
	if HostTarget() == "/" {
		t.Fatal("HostTarget() is empty")
	}
}

func TestParseTargetAndNativeValidation(t *testing.T) {
	target, err := ParseTarget(HostTarget())
	if err != nil || target.String() != HostTarget() {
		t.Fatalf("ParseTarget() = %v, %v", target, err)
	}
	if _, err := ParseTarget("plan9/amd64"); err == nil {
		t.Fatal("ParseTarget() accepted an unsupported target")
	}
	other := Target{GOOS: "linux", GOARCH: "amd64"}
	if other.String() == HostTarget() {
		other = Target{GOOS: "darwin", GOARCH: "arm64"}
	}
	if _, err := normalizedTargets([]Target{other}); err == nil {
		t.Fatal("normalizedTargets() accepted a non-native target")
	}
	if _, err := normalizedTargets([]Target{target, target}); err == nil {
		t.Fatal("normalizedTargets() accepted a duplicate target")
	}
}

func TestRunBuildsDeterministicReleaseAssets(t *testing.T) {
	directory := t.TempDir()
	writeReleaseFile(t, directory, "go.mod", "module example.test/release\n\ngo 1.25.0\n")
	writeReleaseFile(t, directory, "main.go", "package main\nvar version = \"dev\"\nfunc main() {}\n")
	if err := os.Mkdir(filepath.Join(directory, "helper"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeReleaseFile(t, filepath.Join(directory, "helper"), "main.go", "package main\nvar version = \"dev\"\nfunc main() {}\n")
	writeReleaseFile(t, directory, "README.md", "# test\n")
	writeReleaseFile(t, directory, "LICENSE", "test license\n")
	writeReleaseFile(t, directory, "provider.json", "{\"id\":\"test\"}\n")
	dist := filepath.Join(directory, "dist")
	options := Options{Directory: directory, Broker: "test-broker", Command: ".", Version: "v0.1.0", Dist: dist,
		ExtraCommands: map[string]string{"test-broker-exec": "./helper"},
		ExtraFiles:    map[string]string{"providers/test.json": filepath.Join(directory, "provider.json")}}
	if err := Run(t.Context(), options); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(filepath.Join(dist, "checksums.txt")) // #nosec G304 -- test-owned path.
	if err != nil {
		t.Fatal(err)
	}
	asset := filepath.Join(dist, "test-broker_"+strings.ReplaceAll(HostTarget(), "/", "_")+".tar.gz")
	if names := archiveNames(t, asset); !slices.Equal(names, []string{"test-broker", "test-broker-exec", "providers/test.json", "README.md", "LICENSE"}) {
		t.Fatalf("archive names = %v", names)
	}
	assertArchiveMetadata(t, asset)
	if err := Run(t.Context(), options); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(filepath.Join(dist, "checksums.txt")) // #nosec G304 -- test-owned path.
	if err != nil || string(first) != string(second) || strings.Count(string(second), "test-broker_") != 1 {
		t.Fatalf("checksums are not deterministic: %v", err)
	}
}

func TestRunBuildsSignedDeploymentTemplates(t *testing.T) {
	directory := t.TempDir()
	writeReleaseFile(t, directory, "go.mod", "module example.test/release-kit\n\ngo 1.25.0\n")
	writeReleaseFile(t, directory, "main.go", "package main\nvar version = \"dev\"\nfunc main() {}\n")
	if err := os.Mkdir(filepath.Join(directory, "provider"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeReleaseFile(t, filepath.Join(directory, "provider"), "main.go", "package main\nvar version = \"dev\"\nfunc main() {}\n")
	writeReleaseFile(t, filepath.Join(directory, "provider"), "profile.json", "{\"api_version\":\"unyolo.io/test-deployment/v1\"}\n")
	writeReleaseFile(t, filepath.Join(directory, "provider"), "release.json", `{
  "api_version":"unyolo.io/deployment-release-component/v1",
  "provider":"test",
  "name":"test",
  "binary":"test-provider",
  "destination":"bin/test-provider",
  "role":"provider",
  "services":[],
  "agent_contract":true,
  "state_format_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "required":false,
  "setup":{"protocol":"unyolo.io/setup-component/v1","arguments":["setup-component"],"ownership":{"paths":[],"services":[],"accounts":[],"groups":[]}},
  "profile":"profile.json"
}`)
	writeReleaseFile(t, directory, "README.md", "# test\n")
	writeReleaseFile(t, directory, "LICENSE", "test license\n")
	writeReleaseFile(t, directory, "provider.json", "{\"api_version\":\"unyolo.io/setup-provider/v1\",\"id\":\"test\",\"label\":\"Test\",\"selected\":true}\n")
	dist := filepath.Join(directory, "dist")
	options := Options{
		Directory: directory, Broker: "unyolo", Command: ".", Version: "v0.1.0", Dist: dist,
		SourceCommit: strings.Repeat("a", 40), ExtraCommands: map[string]string{"test-provider": "./provider"},
		ExtraFiles:           map[string]string{"providers/test.json": filepath.Join(directory, "provider.json")},
		DeploymentComponents: []string{"provider/release.json"},
	}
	if err := Run(t.Context(), options); err != nil {
		t.Fatal(err)
	}
	asset := filepath.Join(dist, "unyolo_"+strings.ReplaceAll(HostTarget(), "/", "_")+".tar.gz")
	names := archiveNames(t, asset)
	for _, expected := range []string{
		"deployment-kits/artifacts/test-provider",
		"deployment-kits/templates/test/deployment.json",
		"deployment-kits/templates/test/runtime/manifest.json",
		"deployment-kits/templates/test/runtime/manifest.sig",
		"deployment-kits/templates/test/runtime/release.pub",
		"deployment-kits/templates/test/components/test.json",
	} {
		if !slices.Contains(names, expected) {
			t.Fatalf("archive is missing %q: %v", expected, names)
		}
	}
	if slices.Contains(names, "test-provider") {
		t.Fatalf("provider runtime binary escaped the deployment artifact tree: %v", names)
	}
	extracted := extractReleaseArchive(t, asset)
	template := filepath.Join(extracted, "deployment-kits", "templates", "test")
	snapshot, err := profile.Load(template)
	if err != nil {
		t.Fatalf("generated template: %v", err)
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	generated, err := profile.MaterializeReleaseTemplate(snapshot, filepath.Join(extracted, "deployment-kits", "artifacts"), filepath.Join(parent, "host"), "host", "alice", []string{"test"})
	if err != nil {
		t.Fatalf("materialize generated template: %v", err)
	}
	if _, err := profile.Load(generated); err != nil {
		t.Fatalf("load materialized template: %v", err)
	}
}

func TestDeploymentReleaseDescriptorValidation(t *testing.T) {
	valid := deploymentReleaseComponent{
		APIVersion: deploymentReleaseAPIVersion, Provider: "test", Name: "test", Binary: "test-provider",
		Destination: "bin/test-provider", Role: "provider", StateFormatDigest: "sha256:" + strings.Repeat("a", 64),
		Profile: "profile.json", Setup: &bundle.SetupAdapter{Protocol: "unyolo.io/setup-component/v1", Arguments: []string{"setup-component"}},
	}
	binaries := map[string]string{"test-provider": "/tmp/test-provider"}
	if err := validateDeploymentComponent(valid, binaries, map[string]bool{}, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(*deploymentReleaseComponent)
	}{
		{"api", func(value *deploymentReleaseComponent) { value.APIVersion = "bad" }},
		{"provider", func(value *deploymentReleaseComponent) { value.Provider = "../bad" }},
		{"binary", func(value *deploymentReleaseComponent) { value.Binary = "missing" }},
		{"destination", func(value *deploymentReleaseComponent) { value.Destination = "" }},
		{"state digest", func(value *deploymentReleaseComponent) { value.StateFormatDigest = "" }},
		{"operator pair", func(value *deploymentReleaseComponent) { value.OperatorEndpoint = "unix:///tmp/operator.sock" }},
		{"profile", func(value *deploymentReleaseComponent) { value.Profile = "../profile.json" }},
		{"companion profile", func(value *deploymentReleaseComponent) { value.Name = "helper" }},
		{"additional source", func(value *deploymentReleaseComponent) {
			value.AdditionalProfileFiles = []deploymentReleaseFile{{Source: "../source", Destination: "files/source"}}
		}},
		{"additional destination", func(value *deploymentReleaseComponent) {
			value.AdditionalProfileFiles = []deploymentReleaseFile{{Source: "source", Destination: "../files/source"}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := valid
			test.edit(&value)
			if err := validateDeploymentComponent(value, binaries, map[string]bool{}, map[string]bool{}); err == nil {
				t.Fatal("unsafe deployment release descriptor was accepted")
			}
		})
	}
	if err := validateDeploymentComponent(valid, binaries, map[string]bool{"test": true}, map[string]bool{}); err == nil {
		t.Fatal("duplicate component name was accepted")
	}
	if err := validateDeploymentComponent(valid, binaries, map[string]bool{}, map[string]bool{"test": true}); err == nil {
		t.Fatal("duplicate selectable provider was accepted")
	}
}

func TestDeploymentProviderCatalogMustMatchDescriptors(t *testing.T) {
	providers := []string{"github", "huggingface"}
	files := map[string]string{"providers/github.json": "one", "providers/huggingface.json": "two"}
	if err := validateProviderCatalogFiles(files, providers); err != nil {
		t.Fatal(err)
	}
	if err := validateProviderCatalogFiles(map[string]string{"providers/github.json": "one"}, providers); err == nil {
		t.Fatal("incomplete provider catalog was accepted")
	}
	if err := validateProviderCatalogFiles(map[string]string{"providers/github.json": "one", "providers/sudo.json": "two"}, providers); err == nil {
		t.Fatal("mismatched provider catalog was accepted")
	}
}

func TestRunReportsBuildFailure(t *testing.T) {
	directory := t.TempDir()
	writeReleaseFile(t, directory, "go.mod", "module example.test/release-failure\n\ngo 1.25.0\n")
	writeReleaseFile(t, directory, "README.md", "# test\n")
	writeReleaseFile(t, directory, "LICENSE", "test license\n")
	err := Run(t.Context(), Options{
		Directory: directory, Broker: "test-broker", Command: "./cmd/missing", Version: "v0.1.0",
		Dist: filepath.Join(directory, "dist"),
	})
	if err == nil {
		t.Fatal("Run() accepted a missing command")
	}
}

func TestArchiveReportsMissingInput(t *testing.T) {
	directory := t.TempDir()
	binary := filepath.Join(directory, "test-broker")
	writeReleaseFile(t, directory, "test-broker", "binary")
	writeReleaseFile(t, directory, "LICENSE", "test license\n")
	err := archive(filepath.Join(directory, "asset.tar.gz"), Options{Directory: directory}, binary)
	if err == nil {
		t.Fatal("archive() accepted a missing README")
	}
}

func assertArchiveMetadata(t *testing.T, path string) {
	t.Helper()
	reader, closeArchive := openArchive(t, path)
	defer closeArchive()
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		wantMode := int64(0o644)
		if header.Name == "test-broker" || header.Name == "test-broker-exec" {
			wantMode = 0o755
		}
		if header.Mode != wantMode || header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" {
			t.Fatalf("archive metadata for %q = mode %o uid %d gid %d uname %q gname %q", header.Name, header.Mode, header.Uid, header.Gid, header.Uname, header.Gname)
		}
	}
}

func archiveNames(t *testing.T, path string) []string {
	t.Helper()
	reader, closeArchive := openArchive(t, path)
	defer closeArchive()
	var names []string
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, header.Name)
	}
	return names
}

func extractReleaseArchive(t *testing.T, path string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	reader, closeArchive := openArchive(t, path)
	defer closeArchive()
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		destination := filepath.Join(root, filepath.FromSlash(header.Name))
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(header.Mode)) // #nosec G304 -- validated generated archive fixture.
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(file, reader); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func openArchive(t *testing.T, path string) (*tar.Reader, func()) {
	t.Helper()
	file, err := os.Open(path) // #nosec G304 -- generated test fixture.
	if err != nil {
		t.Fatal(err)
	}
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	closeArchive := func() {
		if err := gzipReader.Close(); err != nil {
			t.Error(err)
		}
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}
	return tar.NewReader(gzipReader), closeArchive
}

func writeReleaseFile(t *testing.T, directory, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
