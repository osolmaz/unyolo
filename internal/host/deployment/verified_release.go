package deployment

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"github.com/osolmaz/unyolo/deployment/profile"
)

const maxVerifiedReleases = 64

var (
	verifiedReleaseNamePattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	verifiedTemplatePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9+-]{0,254}$`)
)

//nolint:cyclop // Fail-closed attested-release traversal keeps every unsafe entry check in one trust boundary.
func verifyAttestedReleaseTemplate(stateDir string, snapshot profile.Snapshot) error {
	root := filepath.Join(stateDir, "verified-releases")
	if err := verifyTrustedDirectory(root); err != nil {
		return fmt.Errorf("inspect verified release store: %w", err)
	}
	releases, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	if len(releases) == 0 || len(releases) > maxVerifiedReleases {
		return errors.New("verified release store is empty or exceeds its bound")
	}
	candidate := runtimeTrustFiles(snapshot)
	for _, release := range releases {
		if !verifiedReleaseNamePattern.MatchString(release.Name()) || !release.IsDir() || release.Type()&os.ModeSymlink != 0 {
			return errors.New("verified release store contains an unsafe entry")
		}
		releaseRoot := filepath.Join(root, release.Name())
		if err := verifyTrustedDirectory(releaseRoot); err != nil {
			return err
		}
		templatesRoot := filepath.Join(releaseRoot, "templates")
		if err := verifyTrustedDirectory(templatesRoot); err != nil {
			return err
		}
		templates, err := os.ReadDir(templatesRoot)
		if err != nil {
			return err
		}
		if len(templates) == 0 || len(templates) > 255 {
			return errors.New("verified release template set is empty or exceeds its bound")
		}
		for _, template := range templates {
			if !verifiedTemplatePattern.MatchString(template.Name()) || !template.IsDir() || template.Type()&os.ModeSymlink != 0 {
				return errors.New("verified release template set contains an unsafe entry")
			}
			if matchesRuntimeTrust(filepath.Join(templatesRoot, template.Name()), candidate) {
				return nil
			}
		}
	}
	return errors.New("deployment runtime is not part of a root-verified attested release")
}

func runtimeTrustFiles(snapshot profile.Snapshot) map[string][]byte {
	return map[string][]byte{
		"manifest.json": snapshot.Files[snapshot.Deployment.Runtime.Manifest.Path].Data,
		"manifest.sig":  snapshot.Files[snapshot.Deployment.Runtime.Signature.Path].Data,
		"release.pub":   snapshot.Files[snapshot.Deployment.Runtime.PublicKey.Path].Data,
	}
}

func matchesRuntimeTrust(templateRoot string, candidate map[string][]byte) bool {
	if err := verifyTrustedDirectory(templateRoot); err != nil {
		return false
	}
	runtimeRoot := filepath.Join(templateRoot, "runtime")
	if err := verifyTrustedDirectory(runtimeRoot); err != nil {
		return false
	}
	for name, expected := range candidate {
		path := filepath.Join(runtimeRoot, name)
		data, err := readTrustedFile(path, 2*1024*1024)
		if err != nil || !bytes.Equal(data, expected) {
			return false
		}
	}
	return true
}

func verifyTrustedDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("verified release path is not a protected real directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("verified release path is not owned by the setup worker")
	}
	return nil
}

func readTrustedFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maximum || info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("verified release file is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return nil, errors.New("verified release file is not owned by the setup worker")
	}
	return os.ReadFile(path) // #nosec G304 -- path is fixed below a verified root-owned release directory.
}
