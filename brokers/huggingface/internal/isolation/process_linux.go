//go:build linux

package isolation

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	bkdoctor "github.com/osolmaz/brokerkit/doctor"
)

func readProcStatus(pid int) (procStatus, error) {
	data, err := os.ReadFile(procPath(pid, "status"))
	if err != nil {
		return procStatus{}, err
	}
	return ParseProcStatus(data)
}

// ParseProcStatus adapts the shared process status to HF's check model.
func ParseProcStatus(data []byte) (procStatus, error) {
	status, err := bkdoctor.ParseProcessStatus(data)
	if err != nil {
		return procStatus{}, err
	}
	return procStatus{
		uid: status.FilesystemUID, gid: status.FilesystemGID,
		uidValues: status.UIDs, gidValues: status.GIDs, gids: status.Groups,
		capEff: status.EffectiveCaps, capPrm: status.PermittedCaps,
	}, nil
}

func readProcEnviron(pid int) ([]string, error) {
	data, err := os.ReadFile(procPath(pid, "environ"))
	if err != nil {
		return nil, err
	}
	parts := strings.Split(string(data), "\x00")
	environment := parts[:0]
	for _, item := range parts {
		if item != "" {
			environment = append(environment, item)
		}
	}
	return environment, nil
}

func readProcCWD(pid int) (string, error) { return os.Readlink(procPath(pid, "cwd")) }

func procPath(pid int, name string) string {
	return filepath.Join("/proc", strconv.Itoa(pid), name)
}

func envHasSecretName(environment []string) bool {
	for _, name := range []string{"HF_TOKEN", "HF_TOKEN_PATH", "HUGGING_FACE_HUB_TOKEN", "HF_BROKER_HF_TOKEN", "HF_BROKER_HF_TOKEN_FILE"} {
		if envHasName(environment, name) {
			return true
		}
	}
	return false
}

func envHasName(environment []string, target string) bool {
	_, found := envValue(environment, target)
	return found
}

func envValue(environment []string, target string) (string, bool) {
	for _, item := range environment {
		name, value, _ := strings.Cut(item, "=")
		if name == target {
			return value, true
		}
	}
	return "", false
}

func sameCredentialPath(checkedPath, brokerPath, brokerCWD string) (bool, bool) {
	checked, ok := bkdoctor.AbsolutePath(checkedPath, "")
	if !ok {
		return false, false
	}
	broker, ok := bkdoctor.AbsolutePath(brokerPath, brokerCWD)
	if !ok {
		return false, false
	}
	if checked == broker {
		return true, true
	}
	resolvedChecked, checkedOK := bkdoctor.ResolvedCleanPath(checked)
	resolvedBroker, brokerOK := bkdoctor.ResolvedCleanPath(broker)
	if !checkedOK || !brokerOK {
		return false, true
	}
	return resolvedChecked == resolvedBroker, true
}
