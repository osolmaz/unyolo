package bundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/osolmaz/brokerkit/internal/fsx"
)

const trustedKeyFilename = "trusted-release.pub"

// TrustedPublicKey selects the pinned host key or validates the proposed key
// for a first installation. It does not mutate the host.
func TrustedPublicKey(stateDir, proposedPath string) (path string, needsPin bool, err error) {
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return "", false, errors.New("host state directory must be absolute and normalized")
	}
	pinned := filepath.Join(stateDir, trustedKeyFilename)
	pinnedKey, pinnedErr := readPublicKey(pinned)
	if pinnedErr == nil {
		if proposedPath != "" {
			proposed, proposedErr := readPublicKey(proposedPath)
			if proposedErr != nil || !bytes.Equal(pinnedKey, proposed) {
				return "", false, errors.New("proposed release key does not match the host trust root")
			}
		}
		return pinned, false, nil
	}
	if !errors.Is(pinnedErr, os.ErrNotExist) {
		return "", false, fmt.Errorf("read host release key: %w", pinnedErr)
	}
	if proposedPath == "" {
		return "", false, errors.New("a release public key is required for first installation")
	}
	if _, err := readPublicKey(proposedPath); err != nil {
		return "", false, fmt.Errorf("read proposed release key: %w", err)
	}
	return proposedPath, true, nil
}

// PinTrustedPublicKey atomically establishes the first host release trust root.
func PinTrustedPublicKey(stateDir, proposedPath string) (string, error) {
	selected, needsPin, err := TrustedPublicKey(stateDir, proposedPath)
	if err != nil || !needsPin {
		return selected, err
	}
	key, err := readPublicKey(proposedPath)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}
	pinned := filepath.Join(stateDir, trustedKeyFilename)
	encoded := []byte(base64.StdEncoding.EncodeToString(key) + "\n")
	file, err := os.OpenFile(pinned, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- fixed private host state path.
	if errors.Is(err, os.ErrExist) {
		selected, _, trustErr := TrustedPublicKey(stateDir, proposedPath)
		return selected, trustErr
	}
	if err != nil {
		return "", err
	}
	_, writeErr := file.Write(encoded)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		_ = os.Remove(pinned)
		return "", err
	}
	if err := fsx.SyncDirectory(stateDir); err != nil {
		return "", err
	}
	return pinned, nil
}

func readPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := readBounded(path, 1024)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("release public key is invalid")
	}
	return ed25519.PublicKey(decoded), nil
}
