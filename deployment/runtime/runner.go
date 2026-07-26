package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/deployment/api"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const (
	DefaultTimeout = 2 * time.Minute
	maxStderrBytes = 64 * 1024
)

// Command is an exact signed adapter executable and fixed argument list.
type Command struct {
	Executable string
	Arguments  []string
}

// Secret binds one logical slot to a one-use read-only descriptor.
type Secret struct {
	Name   string
	File   *os.File
	Rotate bool
}

// Runner executes setup adapters with a minimal environment.
type Runner struct {
	Timeout time.Duration
	Getenv  func(string) string
}

// Run sends one request and validates the closed redacted response.
//
//nolint:cyclop // Process launch, framed exchange, limits, cancellation, and exit validation form one trust boundary.
func (runner Runner) Run(ctx context.Context, command Command, request api.Request, secrets []Secret) (api.Response, error) {
	if err := validateCommand(command); err != nil {
		return api.Response{}, err
	}
	if len(secrets) != 0 && len(request.Secrets) != 0 {
		return api.Response{}, errors.New("setup-component request descriptors are runner-owned")
	}
	extraFiles, descriptors, err := prepareSecrets(secrets)
	if err != nil {
		return api.Response{}, err
	}
	request.Secrets = descriptors
	if err := request.Validate(); err != nil {
		return api.Response{}, err
	}
	timeout := runner.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var input, output bytes.Buffer
	stderr := &boundedBuffer{maximum: maxStderrBytes}
	if err := WriteFrame(&input, request); err != nil {
		return api.Response{}, err
	}
	process := exec.CommandContext(commandContext, command.Executable, command.Arguments...) // #nosec G204 -- executable and arguments come from the signed runtime manifest.
	process.Stdin, process.Stdout, process.Stderr = &input, &output, stderr
	process.ExtraFiles = extraFiles
	process.Env = runner.environment()
	if err := process.Run(); err != nil {
		if errors.Is(commandContext.Err(), context.DeadlineExceeded) {
			return api.Response{}, errors.New("setup-component adapter timed out")
		}
		return api.Response{}, fmt.Errorf("setup-component adapter failed: %w", err)
	}
	var response api.Response
	if err := ReadFrame(&output, &response); err != nil {
		return api.Response{}, err
	}
	if output.Len() != 0 {
		return api.Response{}, errors.New("setup-component emitted trailing protocol bytes")
	}
	if response.ComponentID != request.ComponentID {
		return api.Response{}, errors.New("setup-component response identity does not match request")
	}
	if err := response.Validate(); err != nil {
		return api.Response{}, err
	}
	if containsSensitiveProviderFact(response.ProviderFacts) {
		return api.Response{}, errors.New("setup-component response contains a prohibited sensitive field")
	}
	return response, nil
}

func validateCommand(command Command) error {
	if command.Executable == "" || !strings.HasPrefix(command.Executable, "/") {
		return errors.New("setup-component executable must be absolute")
	}
	for _, argument := range command.Arguments {
		if strings.ContainsRune(argument, 0) || len(argument) > 4096 {
			return errors.New("setup-component argument is invalid")
		}
	}
	return nil
}

func prepareSecrets(secrets []Secret) ([]*os.File, []api.SecretDescriptor, error) {
	if len(secrets) > api.MaxCredentialSlots {
		return nil, nil, errors.New("too many setup-component secrets")
	}
	values := append([]Secret(nil), secrets...)
	slices.SortFunc(values, func(a, b Secret) int { return strings.Compare(a.Name, b.Name) })
	files := make([]*os.File, 0, len(values))
	descriptors := make([]api.SecretDescriptor, 0, len(values))
	seen := map[string]bool{}
	for index, secret := range values {
		if seen[secret.Name] || secret.File == nil {
			return nil, nil, errors.New("setup-component secret is invalid or duplicated")
		}
		if err := validateSecretFile(secret.File); err != nil {
			return nil, nil, fmt.Errorf("secret slot %q: %w", secret.Name, err)
		}
		seen[secret.Name] = true
		files = append(files, secret.File)
		descriptors = append(descriptors, api.SecretDescriptor{Name: secret.Name, FD: 3 + index, Rotate: secret.Rotate})
	}
	return files, descriptors, nil
}

func validateSecretFile(file *os.File) error {
	if term.IsTerminal(int(file.Fd())) {
		return errors.New("secret descriptor must not be a terminal")
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return errors.New("inspect secret descriptor")
	}
	if flags&unix.O_ACCMODE != unix.O_RDONLY {
		return errors.New("secret descriptor must be read-only")
	}
	return nil
}

func (runner Runner) environment() []string {
	getenv := runner.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	result := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	if value := strings.TrimSpace(getenv("TMPDIR")); value != "" && strings.HasPrefix(value, "/") {
		result = append(result, "TMPDIR="+value)
	}
	return result
}

type boundedBuffer struct {
	data    bytes.Buffer
	maximum int
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	remaining := buffer.maximum - buffer.data.Len()
	if remaining > 0 {
		_, _ = buffer.data.Write(value[:min(len(value), remaining)])
	}
	return len(value), nil
}

func containsSensitiveProviderFact(data []byte) bool {
	lower := strings.ToLower(string(data))
	for _, term := range []string{"secret", "token", "password", "credential", "authorization", "cookie"} {
		if strings.Contains(lower, `"`+term+`"`) {
			return true
		}
	}
	return false
}
