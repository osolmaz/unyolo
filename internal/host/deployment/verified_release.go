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
	"github.com/osolmaz/unyolo/setup/sourceset"
)

const maxVerifiedReleases = 64

var verifiedReleaseNamePattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// verifyAttestedReleaseTemplate checks that the deployment's runtime trust
// files come from one root-verified source set.
func verifyAttestedReleaseTemplate(stateDir string, snapshot profile.Snapshot) error {
	_, err := verifiedReleaseSource(stateDir, snapshot)
	return err
}

// verifiedReleaseSource returns the exact source-set root that produced the
// supplied deployment snapshot. The generated deployment binds the digest of
// every source file, while the runtime trust bytes provide a second identity
// check against the signed runtime manifest.
//
//nolint:cyclop // Fail-closed attested-release traversal keeps every unsafe entry check in one trust boundary.
func verifiedReleaseSource(stateDir string, snapshot profile.Snapshot) (string, error) {
	root := filepath.Join(stateDir, "verified-releases")
	if err := verifyTrustedDirectory(root); err != nil {
		return "", fmt.Errorf("inspect verified release store: %w", err)
	}
	releases, err := os.ReadDir(root)
	if err != nil {
		return "", err
	}
	if len(releases) == 0 || len(releases) > maxVerifiedReleases {
		return "", errors.New("verified release store is empty or exceeds its bound")
	}
	if snapshot.Deployment.SourceSetDigest == "" {
		return "", errors.New("deployment does not identify its verified source set")
	}
	candidate := runtimeTrustFiles(snapshot)
	for _, release := range releases {
		if !verifiedReleaseNamePattern.MatchString(release.Name()) || !release.IsDir() || release.Type()&os.ModeSymlink != 0 {
			return "", errors.New("verified release store contains an unsafe entry")
		}
		releaseRoot := filepath.Join(root, release.Name())
		if err := verifyTrustedDirectory(releaseRoot); err != nil {
			return "", err
		}
		sourceRoot := filepath.Join(releaseRoot, "source-set")
		if err := verifyTrustedDirectory(sourceRoot); err != nil {
			return "", err
		}
		digest, digestErr := sourceset.Digest(sourceRoot)
		if digestErr != nil {
			return "", fmt.Errorf("digest verified release %q: %w", release.Name(), digestErr)
		}
		if digest == snapshot.Deployment.SourceSetDigest && matchesRuntimeTrust(sourceRoot, candidate) {
			return sourceRoot, nil
		}
	}
	return "", errors.New("deployment runtime is not part of a root-verified attested release")
}

func runtimeTrustFiles(snapshot profile.Snapshot) map[string][]byte {
	return map[string][]byte{
		"manifest.json": snapshot.Files[snapshot.Deployment.Runtime.Manifest.Path].Data,
		"manifest.sig":  snapshot.Files[snapshot.Deployment.Runtime.Signature.Path].Data,
		"release.pub":   snapshot.Files[snapshot.Deployment.Runtime.PublicKey.Path].Data,
	}
}

func matchesRuntimeTrust(sourceRoot string, candidate map[string][]byte) bool {
	runtimeRoot := filepath.Join(sourceRoot, "runtime")
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
