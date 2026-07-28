//go:build linux

package isolation

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	unyolodoctor "github.com/osolmaz/unyolo/internal/host/doctor"
)

func readProcStatus(pid int) (unyolodoctor.ProcessStatus, error) {
	data, err := os.ReadFile(procPath(pid, "status"))
	if err != nil {
		return unyolodoctor.ProcessStatus{}, err
	}
	return ParseProcStatus(data)
}

// ParseProcStatus parses Linux process credentials and capabilities.
func ParseProcStatus(data []byte) (unyolodoctor.ProcessStatus, error) {
	return unyolodoctor.ParseProcessStatus(data)
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
	checked, ok := unyolodoctor.AbsolutePath(checkedPath, "")
	if !ok {
		return false, false
	}
	broker, ok := unyolodoctor.AbsolutePath(brokerPath, brokerCWD)
	if !ok {
		return false, false
	}
	if checked == broker {
		return true, true
	}
	resolvedChecked, checkedOK := unyolodoctor.ResolvedCleanPath(checked)
	resolvedBroker, brokerOK := unyolodoctor.ResolvedCleanPath(broker)
	if !checkedOK || !brokerOK {
		return false, true
	}
	return resolvedChecked == resolvedBroker, true
}
