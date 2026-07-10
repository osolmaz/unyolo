//go:build darwin

package doctor

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

func pathACLState(path string) aclState {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/bin/ls", "-lde", path)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	output, err := command.Output()
	if ctx.Err() != nil || err != nil {
		return aclUnknown
	}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) != "" {
			return aclPresent
		}
	}
	return aclAbsent
}
